# Components & configuration

Every component is configured with environment variables (set in `docker-compose.yml`). Secrets come from the git-ignored `.env` written by `scripts/gen-env.sh`.

## Repository layout

```text
cmd/sdp-controller   controller (PDP): serve, status, revoke
cmd/sdp-gateway      accepting host: firewall, fwknopd, reverse proxy, telemetry
cmd/sdp-client       initiating host: login, connect, get, proxy, load, bench, disconnect
cmd/sdp-pki          lab CA (runs once in the `pki` container)
internal/api         JSON messages between components
internal/iam         OIDC discovery, JWKS, token validation, password+TOTP login, introspection, logout
internal/policy      device registry and role -> service mapping (RBAC)
internal/spa         fwknopd configuration and supervision, iptables default drop, fwknop client
internal/controller  sessions, gateway pushes, IDS alerts, revocation, audit
internal/gateway     session install/revoke, per-request authorization, telemetry windows
internal/client      timed and byte-counted connection set-up, workload, local forwarder
internal/audit       JSON-lines audit trail
config/policy.yaml   services, roles and devices (read by the controller and every AH)
keycloak/            realm import (roles, clients, demo users)
ids/                 IDS service, training, dataset, tests
lab/                 PKI bootstrap and the protected nginx content
scripts/             gen-env, demo, bench, dataset recording
```

## Policy (`config/policy.yaml`)

```yaml
services:
  portal:  { path: /portal/,  roles: [viewer, researcher, admin] }
  records: { path: /records/, roles: [researcher, admin] }
  admin:   { path: /admin/,   roles: [admin] }
devices:
  ih-alice: { owner: alice, services: [portal, records, admin] }
  ih-bob:   { owner: bob,   services: [portal, records, admin] }
  ih-bench-1: { owner: bench, services: [portal] }   # ... ih-bench-5
```

- **Traditional mode** uses only `devices.<id>.services`: a device may open any service listed for it.
- **Proposed mode** additionally requires the token's `preferred_username` to be the device `owner`, and one of the token's realm roles to be listed in `services.<name>.roles`.
- The AH maps the request path to a service by longest prefix and applies the same role check on every request.

The device id is the CN of the device certificate issued by the lab PKI.

## sdp-controller

| Variable | Default | Meaning |
|---|---|---|
| `SDP_MODE` | `traditional` | `traditional` or `proposed` |
| `SDP_POLICY` | `/etc/sdp/policy.yaml` | policy file |
| `SDP_TLS_DIR` | `/etc/sdp/tls` | `ca.crt`, `tls.crt`, `tls.key` |
| `SDP_LISTEN` | `:8443` | mTLS API (IHs on the public network, gateways and IDS on the internal one) |
| `SDP_STATUS_LISTEN` | `127.0.0.1:8081` | loopback admin port (`status`, `revoke`) |
| `SDP_SESSION_TTL` | `5m` | maximum session lifetime (never beyond the token's `exp`) |
| `SDP_REVOKE_SCOPE` | `subject` | on an IDS alert revoke every session of the identity (`subject`) or only the alerted one (`session`) |
| `SDP_SPA` | `true` | make the controller dark: default-drop iptables + fwknopd with one stanza per device |
| `SDP_PUBLIC_SUBNET` / `SDP_TRUSTED_SUBNETS` | lab subnets | interface sniffed by fwknopd / interfaces accepted without SPA |
| `SDP_DEVICE_KEYS_DIR` | `/etc/sdp/devices` | `<device>.keys` static SPA keys of the devices |
| `SDP_SPA_ACCESS_TIMEOUT` | `5` | seconds the controller port stays open after a valid SPA packet |
| `SDP_OIDC_ISSUER` | `https://keycloak:8443/realms/sdp` | Keycloak realm (discovery at start-up) |
| `SDP_OIDC_AUDIENCE` | `sdp-controller` | required `aud` |
| `SDP_OIDC_CLIENT` | `sdp-client` | required `azp` (client the token was issued to) |
| `SDP_KC_ADMIN_CLIENT_ID` / `SDP_KC_ADMIN_CLIENT_SECRET` | `sdp-controller` / from `.env` | confidential client for introspection and user logout |
| `SDP_INTROSPECT` | `true` | ask Keycloak whether the token is still active before granting a session |
| `SDP_AUDIT_LOG` | `/var/log/sdp/audit.jsonl` | audit trail (also printed to stdout) |

API (mutual TLS, the certificate OU selects what a peer may call):

| Endpoint | Caller (OU) | Purpose |
|---|---|---|
| `POST /v1/sessions` | `device` (+ Bearer token in proposed mode) | request a session for a service |
| `DELETE /v1/sessions/{id}` | `device` (owner) | end a session |
| `POST /v1/gateways`, `DELETE /v1/gateways/{id}` | `gateway` | register (heartbeat) / deregister; the answer carries the controller instance id |
| `POST /v1/alerts` | `ids` | IDS alert; revokes the session (and, with scope `subject`, the identity's other sessions) |

Commands: `sdp-controller status [-sessions] [-json]`, `sdp-controller revoke -device ID | -user NAME [-logout] [-reason TEXT]`.

## sdp-gateway

| Variable | Default | Meaning |
|---|---|---|
| `SDP_MODE`, `SDP_POLICY`, `SDP_TLS_DIR`, `SDP_OIDC_*` | as above | `SDP_OIDC_AUDIENCE` defaults to `sdp-gateway` |
| `SDP_PUBLIC_SUBNET` / `SDP_INTERNAL_SUBNET` | lab subnets | public side (fwknopd, proxy) / management side (control API, trusted) |
| `SDP_PROXY_PORT` | `8443` | mTLS reverse proxy on the public address (closed until SPA) |
| `SDP_CONTROL_PORT` | `9443` | mTLS control API on the management address (controller only) |
| `SDP_SPA_PORT` | `62201` | UDP port fwknopd sniffs |
| `SDP_UPSTREAM` | `http://web:80` | protected service |
| `SDP_CONTROLLER_URL` | `https://controller-mgmt:8443` | registration and heartbeat |
| `SDP_IDS_URL` | (empty: no telemetry) | IDS telemetry endpoint (proposed mode) |
| `SDP_TELEMETRY_WINDOW` | `2s` | telemetry window |
| `SDP_GATEWAY_ID` | `gw-<last octet>` | id announced to the controller |

For every session the AH writes an fwknopd stanza (`SOURCE` = IH address, per-session Rijndael and HMAC-SHA256 keys, `FW_ACCESS_TIMEOUT` = remaining session lifetime) and reloads fwknopd blue/green: a second fwknopd starts with the new stanzas and the old one stops once the new one runs, so SPA packets are not lost during reloads. Revocation removes the stanza, deletes the iptables rules fwknopd opened for the address and its conntrack entries, and closes the proxy connections, unless another live session uses the same address.

The proxy strips the `Authorization` header before forwarding (the service only receives `X-SDP-Session`, `X-SDP-Device`, `X-SDP-User`).

### Telemetry features (`sdp-window-v1`)

One vector per session per AH per window: `req_rate`, `bytes_in_rate`, `bytes_out_rate`, `err_ratio`, `mean_latency_ms`, `new_conn_rate`, `open_conns`, `stalled_conns`, `mean_iat_ms`, `iat_cv`, `distinct_paths`. The list is defined in `internal/gateway/features.go` and `ids/sdp_ids/features.py`; a test checks they match.

## sdp-client

| Variable | Default | Meaning |
|---|---|---|
| `SDP_MODE` | `traditional` | |
| `SDP_TLS_DIR` | `/etc/sdp/tls` | device certificate, key and `spa.keys` |
| `SDP_CONTROLLER` / `SDP_CONTROLLER_PORT` | `controller` / `8443` | |
| `SDP_CONTROLLER_SPA` | `true` | knock on the controller before connecting |
| `SDP_OIDC_ISSUER`, `SDP_OIDC_CLIENT` | lab realm, `sdp-client` | |
| `SDP_USERNAME`, `SDP_PASSWORD`, `SDP_OTP_SECRET` | from `.env` | **lab-only shortcut**, see below |
| `SDP_SESSION_FILE` | `/tmp/sdp-session.json` | saved session (token included, mode 0600) |

| Command | Purpose |
|---|---|
| `login [--no-otp]` | IAM login only; prints user, roles, audiences and expiry |
| `connect SERVICE [--no-login] [--no-otp] [--json]` | the full flow, with per-phase timings and bytes |
| `get [PATH] [--no-token]` | one request on the saved session |
| `proxy [--listen 127.0.0.1:8080]` | local plain-HTTP forwarder for the saved session (curl, browsers, `hey`) |
| `load [--duration --think --workers --path]` | closed-loop synthetic workload |
| `bench SERVICE [--runs --pause --duration --think]` | repeated set-ups + workload, JSON for `scripts/bench` |
| `disconnect` | end the saved session |

Exit codes: `0` ok, `1` error, `2` IAM login refused, `3` controller denied, `4` data channel refused.

!!! warning "Lab-only shortcut: passwords and TOTP secrets in the client containers"
    A real user types the password and the six-digit code shown by an authenticator app. To make the demo and the benchmark scriptable, the realm import provisions a known TOTP secret for each demo user (from `.env`) and the same secret is given to that user's client container, which computes the code itself. The realm also allows a TOTP code to be reused within its 30-second period (`otpPolicyCodeReusable`), so that repeated logins in the benchmark do not have to wait for the next code. Neither shortcut belongs outside a lab.

## IDS

| Variable | Default | Meaning |
|---|---|---|
| `IDS_LISTEN` | `0.0.0.0:9443` | telemetry endpoint (mTLS, gateway certificates only) |
| `IDS_STATUS_LISTEN` | `127.0.0.1:9081` | loopback status (`python -m sdp_ids status`) |
| `IDS_MODEL` | `/opt/ids/model.joblib` | model file (`none` = baseline only) |
| `IDS_POLICY` | `both` | `both` (classifier and baseline must agree), `either`, `classifier`, `ueba` |
| `IDS_CONSECUTIVE` | `2` | anomalous windows in a row before alerting |
| `IDS_THRESHOLD` | `0.5` | classifier probability threshold |
| `IDS_UEBA_Z` / `IDS_UEBA_RATIO` | `4` / `5` | baseline deviation: z-score in log space and minimum ratio |
| `IDS_ENFORCE` | `1` | send alerts to the controller (`0`: observe only) |
| `IDS_RECORD_PATH` | (empty) | append every received window to this CSV (dataset recording) |

See [IDS & UEBA](ids.md).

## PKI

`lab/pki-bootstrap.sh` runs once in the `pki` container and writes into the `pki` volume: an ECDSA P-256 CA and one bundle per component (`ca.crt`, `tls.crt`, `tls.key`; devices also get `spa.keys`, and the controller gets a copy of every device's SPA keys). The certificate CN is the component id and the OU its role (`device`, `gateway`, `controller`, `ids`, `server`); the controller, the AHs and the IDS authorize mTLS peers by OU. Each container mounts only its own bundle, read-only, through volume `subpath`.

Simplifications: one CA, no revocation lists, and every gateway replica shares one certificate (CN `sdp-gateway`) so that `--scale` works.

## Audit trail

The controller and every AH write one JSON object per line (`/var/log/sdp/audit.jsonl` and stdout):

```json
{"time":"2026-11-13T10:55:17.208Z","component":"controller","event":"session_revoked","outcome":"revoke",
 "mode":"proposed","session_id":"2393...","device":"ih-alice","username":"alice","subject":"148e...",
 "client_ip":"10.233.0.40","service":"records","reason":"IDS alert from ids: [ueba] req_rate 4971.8/s ..."}
```

Events: `controller_started`, `gateway_registered`, `gateway_deregistered`, `session_request` (allow/deny with reason and decision time), `session_terminated`, `session_expired`, `session_revoked`, `gateway_revoke`, `ids_alert`, `iam_logout`, `admin_revoke`, `api_access` (wrong certificate role); on the AH: `gateway_started`, `session_installed`, `session_revoked`, `request_denied`.
