# iam-ids-sdp

**iam-ids-sdp** is the companion implementation of the article *Enhancing software-defined perimeters with integrated identity solutions and threat detection for robust zero trust security* (Payá, García-Díaz and Gómez, [International Journal of Information Security 24, 178, 2025](https://doi.org/10.1007/s10207-025-01099-9)).

It is a Software-Defined Perimeter (SDP) written in Go that can run in two modes:

- **traditional**: the classic SDP. A device key pair authenticates the initiating host (IH) to the controller over mutual TLS, Single Packet Authorization (SPA, fwknop) opens the accepting host (AH) for that address only, and nothing else is checked;
- **proposed**: the architecture of the paper. Before anything else, the user authenticates with **Keycloak** using **multi-factor authentication** (password + TOTP) and gets a session token whose **realm roles** drive role-based access control. The controller validates the token as well as the device key pair, the accepting host validates it **again on its own** for every request, and an **IDS** (an Apollon-style multi-armed bandit over a pool of classifiers, plus a per-identity behavioural baseline) watches every session. An IDS alert makes the controller **revoke** the session on the gateways and end the user's Keycloak session.

!!! info "Provenance"
    The repository cited by the paper was **empty when the paper was published** (it only held an initial commit). **This implementation was written in 2026 following the paper.** The numbers reported in the paper were obtained by the authors with their own set-up and **have not been regenerated with this code**; anything measured with this repository is labelled as a local measurement. See [Provenance](provenance.md).

## From login to revocation

1. **Authenticate with the IAM.** The IH logs in to Keycloak with password and TOTP code. Keycloak issues a short-lived access token carrying the user's realm roles (`admin`, `researcher`, `viewer`).
2. **Knock and connect to the controller.** The controller is dark too: the IH sends an SPA packet with its device keys, then opens mutual TLS with its device certificate and asks for a service, presenting the token.
3. **Decide.** The controller checks the token (signature against Keycloak's keys, issuer, audience, expiry, client, and online introspection), that the user owns the device, and that one of the user's roles grants the service.
4. **Prepare the accepting hosts.** The controller generates fresh SPA keys for this session alone and installs them on every AH, bound to the IH's address, together with the identity behind the session.
5. **Reach the service.** The IH knocks on the AH, which opens its port for that address. Its reverse proxy re-validates the token and the roles for every request before forwarding to the protected service.
6. **Watch and respond.** The AH reports per-session request features to the IDS every two seconds. When a session deviates strongly from its user's usual behaviour and the classifier pool agrees, the IDS alerts the controller, which revokes the session everywhere (firewall rules and connections on the AHs, the user's Keycloak session) and writes it to the audit log.

## Components

| Component | Code | Role in the paper |
|---|---|---|
| `sdp-controller` | Go, `cmd/sdp-controller` | SDP controller (policy decision point), integrated with the IAM and the IDS |
| `sdp-gateway` | Go, `cmd/sdp-gateway` | Accepting host with default-drop iptables, fwknopd, token-validating reverse proxy, telemetry |
| `sdp-client` | Go, `cmd/sdp-client` | Initiating host: Keycloak login, SPA, mTLS, local forwarder, workloads, benchmark |
| IDS | Python, `ids/` | Apollon-style MAB with Thompson sampling + per-identity baseline (UEBA) |
| Keycloak | `quay.io/keycloak/keycloak:26.8.1` | IAM: realm, MFA (TOTP), realm roles, sessions |
| nginx | `nginx:1.28-alpine` | The protected service (portal, records, admin) |

## Quick start

```bash
./scripts/gen-env.sh                  # random lab secrets in .env (git-ignored)
docker compose up -d --build --wait   # proposed mode: Keycloak, IDS, controller, gateway, nginx, two IHs
./scripts/demo.sh                     # MFA, SPA + mTLS, authorization tests, IDS-driven revocation
```

Continue with [Getting started](getting-started.md), the [Architecture](architecture.md) and the [IDS & UEBA](ids.md) page, which explains exactly what the lab's detection model is and is not.

!!! warning "Research software"
    This is a lab. Some shortcuts are deliberate and documented (the demo users' TOTP secrets are provisioned at realm import and given to the client containers so scripts can log in; gateway replicas share one certificate; state lives in memory). Review [Components & configuration](components.md) before reusing any part of it.
