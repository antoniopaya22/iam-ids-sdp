"""The IDS service.

* ``POST /v1/telemetry`` (mutual TLS, gateway certificates only): telemetry batches from the
  accepting hosts. Every window goes through the detector; alerts are posted to the
  controller (``POST /v1/alerts`` with the IDS certificate), which revokes the session.
* ``GET /status`` on a loopback-only port: counters, model metadata, baselines, recent
  decisions and alerts (``python -m sdp_ids status``).

Configuration (environment): IDS_LISTEN, IDS_STATUS_LISTEN, IDS_TLS_DIR, IDS_CONTROLLER_URL,
IDS_CONTROLLER_NAME, IDS_MODEL, IDS_POLICY, IDS_CONSECUTIVE, IDS_THRESHOLD, IDS_UEBA_Z,
IDS_UEBA_RATIO, IDS_ENFORCE, IDS_RECORD_PATH.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import os
import ssl
import sys
import threading
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import model as model_io
from .dataset import RAW_COLUMNS
from .detector import FALLBACK_PRIOR, Detector
from .features import FEATURE_NAMES, FEATURE_SET
from .ueba import UEBA


def env(key: str, default: str) -> str:
    v = os.environ.get(key, "").strip()
    return v or default


def log(msg: str) -> None:
    print(f"{dt.datetime.now().isoformat(timespec='seconds')} [ids] {msg}", flush=True)


def peer_ou(cert: dict | None) -> tuple[str, str]:
    """(CN, first OU) of a verified peer certificate as returned by getpeercert()."""
    cn = ou = ""
    for rdn in (cert or {}).get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
            elif k == "organizationalUnitName" and not ou:
                ou = v
    return cn, ou


class AlertSink:
    """Posts alerts to the controller over mutual TLS."""

    def __init__(self, url: str, tls_dir: str, server_name: str):
        self.url = url.rstrip("/") + "/v1/alerts"
        ctx = ssl.create_default_context(cafile=os.path.join(tls_dir, "ca.crt"))
        ctx.load_cert_chain(os.path.join(tls_dir, "tls.crt"), os.path.join(tls_dir, "tls.key"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx = ctx
        self.server_name = server_name

    def send(self, alert: dict) -> dict:
        req = urllib.request.Request(self.url, data=json.dumps(alert).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        # urllib verifies the hostname of the URL; the lab URL uses the controller's
        # management alias, which is in its certificate.
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read() or b"{}")


class Recorder:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        self.f = open(path, "a", newline="")
        self.w = csv.DictWriter(self.f, fieldnames=RAW_COLUMNS)
        if new:
            self.w.writeheader()

    def write(self, w: dict) -> None:
        f = w.get("features", {})
        row = {"time": w.get("window_start", ""), "session_id": w.get("session_id", ""),
               "username": w.get("username", ""), "gateway": w.get("gateway", ""),
               "window_secs": w.get("window_secs", 0), **{k: f.get(k, 0.0) for k in FEATURE_NAMES}}
        with self.lock:
            self.w.writerow(row)
            self.f.flush()


class IDS:
    def __init__(self, detector: Detector, sink: AlertSink | None, enforce: bool, recorder: Recorder | None):
        self.detector = detector
        self.sink = sink
        self.enforce = enforce
        self.recorder = recorder
        self.alerts = deque(maxlen=100)
        self.batches = 0

    def handle_batch(self, batch: dict) -> int:
        if batch.get("feature_set") != FEATURE_SET:
            raise ValueError(f"feature set {batch.get('feature_set')!r}, expected {FEATURE_SET}")
        self.batches += 1
        n = 0
        for w in batch.get("windows") or []:
            n += 1
            if self.recorder:
                self.recorder.write(w)
            d = self.detector.process(w)
            if d.anomalous and not d.alert:
                log(f"anomalous window: session {d.session_id} ({d.identity}) on {d.gateway}: {d.reason}")
            if d.alert:
                alert = {"session_id": d.session_id, "subject": w.get("subject", ""), "username": w.get("username", ""),
                         "client_ip": w.get("client_ip", ""), "gateway": d.gateway,
                         "detector": "apollon-mab+ueba" if d.classifier_anomalous is not None else "ueba",
                         "reason": d.reason, "score": d.probability or 0.0, "severity": "high",
                         "time": dt.datetime.now(dt.timezone.utc).isoformat()}
                record = {"alert": alert, "enforced": False, "controller": None}
                self.alerts.append(record)
                log(f"ALERT session {d.session_id} ({d.identity}): {d.reason}")
                if self.enforce and self.sink:
                    threading.Thread(target=self._deliver, args=(record,), daemon=True).start()
        return n

    def _deliver(self, record: dict) -> None:
        alert = record["alert"]
        try:
            resp = self.sink.send(alert)
            record["enforced"], record["controller"] = True, resp
            log(f"controller answered {resp}")
        except Exception as e:  # noqa: BLE001 - report and allow a new alert later
            record["controller"] = {"error": str(e)}
            log(f"could not deliver alert for {alert['session_id']}: {e}")
            self.detector.forget_alert(alert["session_id"])

    def status(self) -> dict:
        m = self.detector.model
        return {
            "feature_set": FEATURE_SET,
            "policy": self.detector.policy, "consecutive": self.detector.consecutive,
            "threshold": self.detector.threshold, "enforce": self.enforce,
            "recording": self.recorder.path if self.recorder else None,
            "model": None if m is None else {"arms": m.arms, "meta": m.meta},
            "counters": {**self.detector.counters, "batches": self.batches},
            "baselines": self.detector.ueba.snapshot(),
            "alerts": list(self.alerts),
            "recent": list(self.detector.recent)[-30:],
        }


def make_handler(ids: IDS, require_ou: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sdp-ids"
        sys_version = ""

        def log_message(self, fmt, *args):  # quiet
            pass

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if require_ou is None and self.path.startswith("/status"):
                return self._send(200, ids.status())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if require_ou is None or self.path != "/v1/telemetry":
                return self._send(404, {"error": "not found"})
            cn, ou = peer_ou(self.connection.getpeercert())
            if ou != require_ou:
                return self._send(403, {"error": f"{require_ou} certificate required"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 4 << 20:
                    return self._send(413, {"error": "batch too large"})
                n = ids.handle_batch(json.loads(self.rfile.read(length)))
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, {"windows": n})

    return Handler


def split_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host or "0.0.0.0", int(port)


def build_from_env() -> tuple[IDS, dict]:
    tls_dir = env("IDS_TLS_DIR", "/etc/sdp/tls")
    model_path = env("IDS_MODEL", "/opt/ids/model.joblib")
    m = None
    if model_path != "none" and os.path.exists(model_path):
        m = model_io.load(model_path)
        log(f"model {model_path}: arms {m.arms}, holdout {m.meta.get('holdout', {}).get('accuracy')}")
    else:
        log(f"no model at {model_path}: baseline (UEBA) only")
    prior = (m.ueba_prior if m and m.ueba_prior else None) or FALLBACK_PRIOR
    ueba = UEBA(prior, z_threshold=float(env("IDS_UEBA_Z", "4")), min_ratio=float(env("IDS_UEBA_RATIO", "5")))
    det = Detector(m, ueba, policy=env("IDS_POLICY", "both"), consecutive=int(env("IDS_CONSECUTIVE", "2")),
                   threshold=float(env("IDS_THRESHOLD", "0.5")))
    sink = AlertSink(env("IDS_CONTROLLER_URL", "https://controller-mgmt:8443"), tls_dir,
                     env("IDS_CONTROLLER_NAME", "controller-mgmt"))
    rec_path = env("IDS_RECORD_PATH", "")
    rec = Recorder(rec_path) if rec_path else None
    enforce = env("IDS_ENFORCE", "1").lower() in ("1", "true", "yes", "on")
    return IDS(det, sink, enforce, rec), {"tls_dir": tls_dir}


def serve() -> int:
    ids, cfg = build_from_env()
    tls_dir = cfg["tls_dir"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(tls_dir, "tls.crt"), os.path.join(tls_dir, "tls.key"))
    ctx.load_verify_locations(os.path.join(tls_dir, "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    api = ThreadingHTTPServer(split_addr(env("IDS_LISTEN", "0.0.0.0:9443")), make_handler(ids, "gateway"))
    api.socket = ctx.wrap_socket(api.socket, server_side=True)
    status = ThreadingHTTPServer(split_addr(env("IDS_STATUS_LISTEN", "127.0.0.1:9081")), make_handler(ids, None))
    threading.Thread(target=status.serve_forever, daemon=True).start()
    log(f"listening on {api.server_address} (policy {ids.detector.policy}, enforce {ids.enforce}, "
        f"recording {ids.recorder.path if ids.recorder else 'off'})")
    with open("/tmp/ids-ready", "w") as f:
        f.write("ok\n")
    try:
        api.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def status_cli(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m sdp_ids status")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--addr", default=env("IDS_STATUS_LISTEN", "127.0.0.1:9081"))
    args = ap.parse_args(argv)
    with urllib.request.urlopen(f"http://{args.addr}/status", timeout=5) as r:  # noqa: S310 - loopback
        st = json.loads(r.read())
    if args.json:
        print(json.dumps(st, indent=2))
        return 0
    c = st["counters"]
    print(f"policy {st['policy']} (x{st['consecutive']} windows), enforce {st['enforce']}: "
          f"{c['windows']} windows, {c['anomalous']} anomalous, {c['alerts']} alerts")
    if st["model"]:
        h = st["model"]["meta"].get("holdout", {})
        print(f"model arms {st['model']['arms']}; hold-out accuracy {h.get('accuracy')} "
              f"(TPR {h.get('true_positive_rate')}, FPR {h.get('false_positive_rate')})")
    for ident, b in st["baselines"].items():
        print(f"baseline {ident}: {b['req_rate']['typical']} req/s typical, "
              f"{b['bytes_out_rate']['typical']:.0f} B/s out, {b['windows_learnt']} windows learnt")
    for a in st["alerts"]:
        al = a["alert"]
        print(f"alert {al['time']} session {al['session_id']} ({al['username']}): {al['reason']} "
              f"-> controller {a['controller']}")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "serve"
    if cmd == "serve":
        return serve()
    if cmd == "status":
        return status_cli(argv[1:])
    print("usage: python -m sdp_ids [serve|status [--json]]", file=sys.stderr)
    return 2
