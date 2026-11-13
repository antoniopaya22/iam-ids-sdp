# Provenance

## What the repository contained before

The repository `antoniopaya22/iam-ids-sdp` is the one named in the paper's data-availability statement. When the paper was published (July 2025) it contained only an initial commit: a licence file, a `.gitignore` and a one-line README. No code, configuration or data from the authors' experiments was ever published in it.

## What this implementation is

**This code was written in 2026, following the paper** (sections 2.4–2.6 for the IAM, IDS and UEBA concepts, section 5 for the architecture and the complete flow of Sect. 5.6, section 6.1 for the performance methodology). It implements the architecture as described there, with the components the paper names: Keycloak for IAM (MFA, RBAC, session tokens), an IDS built on the Apollon approach (multi-armed bandit with Thompson sampling over a classifier pool), an SDP with mTLS and SPA.

- It is **not** the code the authors used to produce the paper's results.
- The paper's numbers (Tables 2–5, the security scenarios) were obtained by the authors with their own set-up and are quoted in this documentation **as reported in the paper**. They **have not been regenerated** with this code.
- Anything measured with this repository (`scripts/bench/run.sh`, the IDS hold-out metrics) is labelled as a **local measurement**, together with how it was produced.

## Differences from the paper and simplifications

| Topic | Paper | This implementation |
|---|---|---|
| IDS model | Apollon, evaluated on public intrusion datasets (CIC-IDS2017/2018, CIC-DDoS2019, UNSW-NB15) | Apollon's MAB code (Apache-2.0, vendored and credited) over a small classifier pool, trained at image build time on **benign lab workloads** recorded in the lab; features are per-session request statistics, not network flows. A real Apollon model can be plugged in (see [IDS & UEBA](ids.md)). |
| UEBA | IAM context fed into the IDS to detect deviations from normal behaviour | Per-identity baseline (EWMA of request and byte rates in log space, population prior) combined with the classifier pool |
| MFA | TOTP, hardware tokens or push notifications | TOTP with Keycloak's direct grant; demo secrets provisioned at realm import (lab-only shortcut) |
| Token check by the controller | Validated "against the IAM system" | Offline JWKS validation plus online token introspection |
| AH independence | AH equipped with its own IAM capabilities | AH validates tokens with Keycloak's keys and re-applies RBAC from its own copy of the policy; it does not run its own IdP |
| Response to alerts | Isolate or terminate the session | Session revoked on every AH (stanza, firewall rules, conntrack, open connections, token `sid`), user logged out of Keycloak, audit trail |
| Decentralised environments / blockchain (Sect. 5.2) | Discussed | Not implemented |
| Credential theft and DoS experiments (Sect. 6.2) | Simulated attacks | Not reproduced: no attack tooling in this repository; only authorization tests and a monitoring test with a standard benchmarking tool |
| Performance testbed | Ubuntu 22.04, AMD Ryzen 5 5000, 16 GB, Docker | Any Linux host with Docker; results are local measurements |
| State | — | Sessions in the controller's memory; gateways drop sessions when the controller restarts |
| PKI | — | One lab CA created at start-up; gateway replicas share a certificate |

## Licences

The code of this repository is under the MIT licence. `ids/sdp_ids/apollon_mab.py` is derived from [Apollon](https://github.com/antoniopaya22/apollon) and remains under the Apache License 2.0; its licence and notice are in `ids/third_party/apollon/`.
