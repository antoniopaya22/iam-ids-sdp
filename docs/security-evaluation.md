# Security evaluation

## What the paper evaluated

Section 6.2 of the paper compares the traditional SDP with the proposed architecture under two threat families, in controlled conditions, focusing on detection, response time and resilience. The scenarios and results below are summarised **as reported in the paper**; they were not reproduced with this repository.

| Scenario (paper) | Traditional SDP, as reported in the paper | Proposed SDP, as reported in the paper |
|---|---|---|
| **Credential theft**: an adversary obtains a legitimate user's private key | Succeeded whenever the adversary could also present the user's address/hostname: once the key pair is accepted, the controller grants every resource of that user without further scrutiny | Blocked in every test: MFA stops the login without the second factor, and behavioural monitoring after authentication flags atypical activity, leading to session termination or administrator intervention |
| **Volumetric DoS from an unauthorised device** | Neutralised by SPA: a host without valid SPA credentials cannot open a session, so its traffic is dropped at the boundary | Same (SPA is unchanged) |
| **Resource exhaustion from an authorised device** (insider with a valid mTLS session) | Not monitored after authentication, so an insider can degrade availability | Detected by continuous analysis of the authenticated user's traffic with the Apollon IDS; the paper quotes Apollon's published DDoS results (detection rate 0.9691 and accuracy 0.9996 on PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN, NTP, DNS and SNMP attacks) and its ability to detect about half of the adversarial examples (ZOO, HopSkipJump, W-GAN) that evade conventional classifiers |

The paper's conclusion is that IAM and IDS close two gaps of the traditional model: a stolen device credential is no longer sufficient, and authenticated sessions remain under observation.

## What this repository demonstrates

This repository is a defensive implementation. It contains **no attack tooling**: no traffic generators other than ordinary benchmarking tools, no exploit or credential-abuse scripts. Its checks are plain authorization tests and a monitoring test, all in `scripts/demo.sh`:

| Property (paper) | Check in the lab | Mechanism |
|---|---|---|
| Unauthorised hosts cannot even see the services | Before SPA the controller port, the AH port and the private service are unreachable from an IH | default-drop iptables + fwknopd on the controller and the AH; private network only reachable through an AH |
| The device credential alone is not enough (proposed) | A session request with a valid device certificate but **no token** is refused (401) | controller requires a valid Keycloak token bound to the device's owner |
| MFA (proposed) | Password without the TOTP code is refused by Keycloak | Keycloak direct grant with OTP |
| Least privilege (RBAC) | bob (viewer) is refused `records` (403); the AH refuses `/admin/` on bob's portal session | role → service mapping at the controller and at the AH |
| Decentralised verification | The AH refuses a request without the token on an otherwise valid session (401) | AH validates every token with Keycloak's keys on its own |
| Continuous monitoring and response | After 20 s of normal use, a 10 s HTTP load test with `hey` on the user's own session makes the IDS alert; the controller revokes the session on the AH (rules, connections, token `sid`) and in Keycloak; the user must log in again with MFA; other users are unaffected | AH telemetry → IDS (MAB + per-identity baseline) → controller `POST /v1/alerts` |
| Traditional baseline | In traditional mode bob's device reaches `records`: only the device key pair is checked | `scripts/demo.sh` in traditional mode |

The monitoring check uses an ordinary benchmarking tool against the user's own authorised session, i.e. the situation the paper describes as an authorised device consuming far more than usual; it does not reproduce any of the paper's attack experiments.

## Not reproduced here

- The credential-theft experiment and its success rates.
- Volumetric attacks of any kind, and the DDoS detection figures, which come from the Apollon paper and its datasets.
- The adversarial machine-learning results (ZOO, HopSkipJump, W-GAN). The lab's model is trained on a small set of benign lab workloads (see [IDS & UEBA](ids.md)) and says nothing about robustness to adversarial examples; use the [Apollon repository](https://github.com/antoniopaya22/apollon) for that.
