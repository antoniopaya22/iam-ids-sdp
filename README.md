# iam-ids-sdp

[![Paper](https://img.shields.io/badge/IJIS_2025-10.1007%2Fs10207--025--01099--9-0E7490)](https://doi.org/10.1007/s10207-025-01099-9)
[![CI](https://github.com/antoniopaya22/iam-ids-sdp/actions/workflows/ci.yml/badge.svg)](https://github.com/antoniopaya22/iam-ids-sdp/actions/workflows/ci.yml)
[![Docs](https://github.com/antoniopaya22/iam-ids-sdp/actions/workflows/docs.yml/badge.svg)](https://antoniopaya22.github.io/iam-ids-sdp/)
[![License: MIT](https://img.shields.io/github/license/antoniopaya22/iam-ids-sdp?color=green)](LICENSE)

Companion implementation of **[Enhancing software-defined perimeters with integrated identity solutions and threat detection for robust zero trust security](https://doi.org/10.1007/s10207-025-01099-9)** (*International Journal of Information Security* 24, 178, 2025). A Software-Defined Perimeter in Go (controller, accepting host, initiating host; mutual TLS and fwknop Single Packet Authorization) that runs in **traditional** mode (device key pairs only) or in the paper's **proposed** mode: users authenticate with **Keycloak** using **MFA** (password + TOTP), realm roles drive **RBAC** at the controller *and* at every accepting host, which validates each token on its own, and an **IDS** (Apollon-style multi-armed bandit over a classifier pool plus a per-identity behavioural baseline) watches every session and makes the controller **revoke** it (gateways and Keycloak) when it deviates.

📖 **Documentation: <https://antoniopaya22.github.io/iam-ids-sdp/>**

> [!NOTE]
> **Provenance.** This repository was **empty when the paper was published** (initial commit only). The implementation was **written in 2026 following the paper**. Results quoted from the paper were obtained by the authors as reported there and **have not been regenerated with this code**; numbers produced by this repository are labelled as local measurements. See [Provenance](https://antoniopaya22.github.io/iam-ids-sdp/provenance/).

| Component | Code | Role |
|---|---|---|
| `sdp-controller` | Go | Policy decision point: mTLS API, token validation (JWKS + introspection), RBAC, per-session SPA keys, IDS alerts → revocation, audit log |
| `sdp-gateway` | Go | Accepting host: default-drop iptables + fwknopd, mTLS reverse proxy that re-validates token and roles, per-session telemetry |
| `sdp-client` | Go | Initiating host: Keycloak login with TOTP, SPA, mTLS, local forwarder, workloads, benchmark |
| IDS | Python | Thompson-sampling MAB (derived from [Apollon](https://github.com/antoniopaya22/apollon), Apache-2.0) + UEBA baseline |
| Keycloak | `quay.io/keycloak/keycloak:26.8.1` | Realm `sdp`: roles admin/researcher/viewer, demo users with OTP |

## Quick start

Requirements: Linux, Docker Engine 26+ with Compose 2.30+.

```bash
./scripts/gen-env.sh                  # random lab secrets in .env (git-ignored)
docker compose up -d --build --wait   # Keycloak, IDS, controller, gateway, nginx, two initiating hosts
./scripts/demo.sh                     # PASS/FAIL checks
```

```text
[1] Before SPA: controller, accepting host and service are invisible
  PASS alice: controller tcp/8443 filtered
[2] IAM: multi-factor authentication with Keycloak
  PASS password without the TOTP code is refused
[3] Happy path: alice opens the portal
  PASS MFA token -> SPA + mTLS controller -> SPA accepting host -> HTTP 200
[4] Authorization tests
  PASS no token: the controller refuses the session (401) even with a valid device certificate
  PASS wrong role: bob (viewer) is refused records (403)
[5] Monitoring: IDS (Apollon MAB + per-identity baseline) and revocation
  PASS IDS raised an alert for alice's session ...
  PASS Keycloak session of alice ended (audit: iam_logout)
[6] Recovery: a new MFA login gives alice a new session
All checks passed.
```

Traditional mode: `SDP_MODE=traditional COMPOSE_PROFILES= docker compose up -d --wait`. Local benchmark of both modes on the paper's four topologies: `./scripts/bench/run.sh [--quick]` (CSV in `results/`).

Tests:

```bash
go vet ./... && go test -race ./...
pip install -r ids/requirements-dev.txt && (cd ids && python -m pytest -q)
```

More: [Getting started](https://antoniopaya22.github.io/iam-ids-sdp/getting-started/) · [Architecture](https://antoniopaya22.github.io/iam-ids-sdp/architecture/) · [IAM](https://antoniopaya22.github.io/iam-ids-sdp/iam/) · [IDS & UEBA](https://antoniopaya22.github.io/iam-ids-sdp/ids/) · [Security evaluation](https://antoniopaya22.github.io/iam-ids-sdp/security-evaluation/) · [Performance evaluation](https://antoniopaya22.github.io/iam-ids-sdp/performance/)

> [!WARNING]
> Research software and a lab. Demo users' TOTP secrets are provisioned at realm import and given to the client containers so the scripts can log in; this and the other documented shortcuts must not be reused outside a lab. The lab's IDS model is trained on benign lab workloads only: read [what it is and is not](https://antoniopaya22.github.io/iam-ids-sdp/ids/).

## Research line

| Year | Work | Code |
|---|---|---|
| 2022 | Egida: automated security configuration deployment ([Computers & Security](https://doi.org/10.1016/j.cose.2022.102638)) | [Egida-Kassandra/egida](https://github.com/Egida-Kassandra/egida) |
| 2024 | SecureSDP: Bridge-model SDP with dynamic hardening ([IJIS](https://doi.org/10.1007/s10207-024-00863-7)) | [Software-Defined-Perimeter](https://github.com/antoniopaya22/Software-Defined-Perimeter) (fwknop lab) · [Secure-SDP](https://github.com/antoniopaya22/Secure-SDP) |
| 2024 | Apollon: IDS robust to adversarial ML ([Computers & Security](https://doi.org/10.1016/j.cose.2023.103546)) | [apollon](https://github.com/antoniopaya22/apollon) |
| 2025 | **IAM + IDS for SDP** ([IJIS](https://doi.org/10.1007/s10207-025-01099-9)) | **this repository** |

Details: [Research line](https://antoniopaya22.github.io/iam-ids-sdp/research-line/).

## Citation

If you use this work, please cite the article (see also [`CITATION.cff`](CITATION.cff)):

```bibtex
@article{paya2025enhancing,
  title   = {Enhancing software-defined perimeters with integrated identity solutions and threat detection for robust zero trust security},
  author  = {Pay{\'a}, Antonio and Garc{\'i}a-D{\'i}az, Vicente and G{\'o}mez, Alberto},
  journal = {International Journal of Information Security},
  volume  = {24},
  number  = {4},
  pages   = {178},
  year    = {2025},
  doi     = {10.1007/s10207-025-01099-9}
}
```

## License

[MIT](LICENSE). `ids/sdp_ids/apollon_mab.py` is derived from Apollon and stays under the Apache License 2.0 (see `ids/third_party/apollon/`).
