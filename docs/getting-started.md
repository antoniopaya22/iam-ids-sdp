# Getting started

## Requirements

- Linux with Docker Engine 26+ and Docker Compose 2.30+ (volume `subpath`, `--wait`, `depends_on.required`).
- About 3 GB of free memory for the proposed mode (Keycloak is the largest container).
- To work on the code: Go 1.25+ and Python 3.12.

Nothing is published on host ports: the three lab networks are internal Docker networks and every interaction goes through `docker compose exec`.

## Start the lab

```bash
./scripts/gen-env.sh                  # writes .env with random secrets (once)
docker compose up -d --build --wait
```

`gen-env.sh` creates the git-ignored `.env` with the Keycloak admin password, the controller's client secret, the demo users' passwords and their demo TOTP secrets. `.env.example` documents every variable. The first start builds four images, creates the PKI in a Docker volume (`pki` one-shot container) and imports the Keycloak realm; it takes one to two minutes.

```text
$ docker compose ps --format '{{.Service}}: {{.Status}}'
controller: Up (healthy)
gateway: Up (healthy)
ids: Up (healthy)
ih-alice: Up
ih-bob: Up
keycloak: Up (healthy)
web: Up
```

## Run the demo

```bash
./scripts/demo.sh          # about 1.5 minutes
./scripts/demo.sh --quick  # shorter baseline and load test (used by CI)
```

It prints `PASS`/`FAIL` for each check and exits non-zero on failure:

| Step | What is checked |
|---|---|
| 1 | Before SPA, alice cannot open the controller port, the accepting host port, or reach the protected nginx |
| 2 | Keycloak refuses alice's password without the TOTP code; with it, the token carries the role `researcher` |
| 3 | Happy path: token → SPA + mTLS to the controller → SPA to the AH → HTTP 200 (with per-phase timings and bytes) |
| 4 | No token → controller 401; bob (viewer) asking for `records` → 403; the AH refuses `/admin/` on bob's portal session and refuses a request without the token |
| 5 | Alice uses the portal normally for 20 s, then runs `hey -z 10s -c 10` through her session; the IDS raises an alert, the controller revokes the session (AH rules and connections, Keycloak session), the AH is dark to alice again, bob is unaffected |
| 6 | A new MFA login gives alice a new working session |

Example (abridged):

```text
[3] Happy path: alice opens the portal
      1. IAM login (password + TOTP)         56.4 ms    6322 B
      2. SPA to the controller               47.9 ms     225 B
      3. mTLS session request                71.0 ms    6199 B
      4. SPA to 1 accepting host(s)         115.0 ms     225 B
      5. first request /portal/               3.0 ms    5893 B
      gw-129 -> HTTP 200
  PASS MFA token -> SPA + mTLS controller -> SPA accepting host -> HTTP 200
...
[5] Monitoring: IDS (Apollon MAB + per-identity baseline) and revocation
    alert ... session f100... (alice): req_rate 3947.2/s is 2798x the baseline of alice (1.4/s, z=13.1); classifier LogisticRegression (Thompson-sampled) p=1.00; 2 consecutive windows -> controller {'action': 'revoked', ...}
  PASS IDS raised an alert for alice's session f1009776169e2a04647bdb49
  PASS controller session state: revoked by the IDS alert
  PASS Keycloak session of alice ended (audit: iam_logout)
  PASS alice's session no longer reaches the service
...
All checks passed.
```

## Explore by hand

```bash
# who is registered, which sessions exist
docker compose exec controller sdp-controller status -sessions

# log in only (password + TOTP), print the token's roles and audiences
docker compose exec ih-alice sdp-client login

# full flow, then requests on the saved session
docker compose exec ih-alice sdp-client connect records
docker compose exec ih-alice sdp-client get /records/
docker compose exec ih-alice sdp-client get /admin/          # 403: no session grants admin

# use ordinary tools through the session (local forwarder on the IH's loopback)
docker compose exec -d ih-alice sdp-client proxy --listen 127.0.0.1:8080
docker compose exec ih-alice curl -s http://127.0.0.1:8080/records/

# IDS view: model, baselines per identity, recent alerts
docker compose exec ids python -m sdp_ids status

# audit trail of the controller and of the gateway (JSON lines)
docker compose exec controller tail -n 20 /var/log/sdp/audit.jsonl
docker compose exec gateway tail -n 20 /var/log/sdp/audit.jsonl

# administrator intervention: end every session of a user and their Keycloak session
docker compose exec controller sdp-controller revoke -user alice -logout
```

## Switch to traditional mode

The mode is read from `SDP_MODE`; `COMPOSE_PROFILES=proposed` additionally starts Keycloak and the IDS.

```bash
docker compose down
SDP_MODE=traditional COMPOSE_PROFILES= docker compose up -d --wait
SDP_MODE=traditional COMPOSE_PROFILES= ./scripts/demo.sh
```

In traditional mode the demo shows the gap the paper addresses: bob's device reaches `records` because only the device key pair is checked. Edit `.env` to make a mode the default.

## Scale the accepting hosts

```bash
docker compose up -d --wait --scale gateway=5
docker compose exec ih-alice sdp-client connect portal   # one SPA + first request per AH
```

Each replica registers with the controller (`gw-<last octet of its public address>`); a session is installed on every registered AH.

## Tests

```bash
go vet ./... && go test -race ./...
python -m pip install -r ids/requirements-dev.txt && (cd ids && python -m pytest -q)
```

## Clean up

```bash
COMPOSE_PROFILES=proposed,bench docker compose down -v --remove-orphans
```

`-v` also deletes the PKI and IDS volumes; the next start creates a new PKI.
