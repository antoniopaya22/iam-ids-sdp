# Performance evaluation

## Methodology of the paper

Section 6.1 of the paper measures the overhead of adding IAM and IDS to the SDP on four topologies of increasing size, each run in the traditional and in the proposed configuration (Keycloak + Apollon IDS), every scenario repeated 10 times and averaged. HTTP traffic is generated from the IHs to the AHs with synthetic workloads. All components ran in Docker on one machine (Ubuntu 22.04, AMD Ryzen 5 5000 series, 16 GB RAM).

| Topology | Initiating hosts | Controllers | Accepting hosts |
|---|---|---|---|
| 1. Simple | 1 | 1 | 1 |
| 2. Moderate | 1 | 1 | 2 |
| 3. Complex | 1 | 1 | 5 |
| 4. Highly complex | 5 | 1 | 10 |

Metrics: **connection set-up time** (IH authenticates with the controller and establishes a session with the AH), **request size** (data exchanged for authentication, token exchange and session establishment) and **throughput** (successfully processed requests in a 10-minute window).

## Results as reported in the paper

The following values are **as reported in the paper** (Tables 2–5). They were not regenerated with this code.

| Topology | Metric | Traditional SDP | Proposed SDP |
|---|---|---|---|
| 1 (1 IH, 1 AH) | Connection set-up time (ms) | 103 | 181 |
| | Request size (KB) | 1.2 | 4.5 |
| | Throughput (requests / 10 min) | 5812 | 5809 |
| 2 (1 IH, 2 AHs) | Connection set-up time (ms) | 115 | 180 |
| | Request size (KB) | 1.3 | 4.5 |
| | Throughput (requests / 10 min) | 5810 | 5806 |
| 3 (1 IH, 5 AHs) | Connection set-up time (ms) | 137 | 230 |
| | Request size (KB) | 1.2 | 4.3 |
| | Throughput (requests / 10 min) | 5811 | 5808 |
| 4 (5 IHs, 10 AHs), per IH | Connection set-up time (ms) | 143 | 247 |
| | Request size (KB) | 1.2 | 4.5 |
| | Throughput (requests / 10 min) | 2532 | 2213 |

As reported in the paper, the proposed architecture adds roughly 75–100 ms to the connection set-up (the extra token request and its validation), about 3.3 KB of data, and leaves throughput almost unchanged except in topology 4, where all components share one host; the paper also reports that throughput decreases linearly, and in parallel for both architectures, as the number of AHs grows from 1 to 20 with one IH (Fig. 7).

## Running the local benchmark

`scripts/bench/run.sh` reproduces the **methodology** on your machine:

```bash
./scripts/gen-env.sh                     # if .env does not exist yet
./scripts/bench/run.sh                   # both modes, topologies 1-4, 10 set-ups, 60 s workload (~25 min)
./scripts/bench/run.sh --quick           # 3 set-ups, 10 s workload (~6 min)
./scripts/bench/run.sh --modes proposed --topologies 1,4 --runs 20 --duration 600
```

For each mode it recreates the lab (`docker compose down` + `up`) with the `bench` profile, scales the gateways with `--scale gateway=N` and uses the benchmark IHs `ih-bench-1` ... `ih-bench-5` (user `bench`, role `viewer`). Each IH, in parallel with the others:

1. runs one warm-up set-up that is not reported (the first token request after Keycloak starts is several times slower), then measures `--runs` connection set-ups with `sdp-client bench`: in proposed mode the Keycloak login (password + TOTP), then SPA to the controller, the mTLS session request (token validation, introspection, RBAC, installing the session on every AH), SPA to every AH and the first request to every AH. Between set-ups the session is closed and the client waits 5.5 s so that the controller's SPA door (5 s) has closed again and every set-up starts from a dark perimeter;
2. runs a closed-loop workload on its last session: one worker sends a request to the next AH (round robin), waits for the answer, sleeps 100 ms, and repeats for `--duration` seconds. Throughput is the number of successful requests, extrapolated to 10 minutes.

**Request size** is measured as the bytes written and read on the sockets of the client during the set-up (TCP payloads, i.e. TLS records including handshakes and certificates, plus the SPA UDP payloads), not the HTTP bodies only. It is therefore not comparable with the paper's KB values, which count request sizes.

In proposed mode the IDS stays active during the benchmark (the workload is well within the normal envelope and does not trigger it).

Output, in `results/bench-<UTC time>/` (git-ignored):

| File | Content |
|---|---|
| `environment.txt` | date, commit, CPU, memory, kernel, Docker version, parameters |
| `runs.csv` | one row per set-up: per-phase milliseconds and bytes (`token`, `controller_spa`, `controller`, `gateway_spa`, `first_request`), totals |
| `load.csv` | one row per IH and topology: successful/failed requests, rate, requests per 10 min, mean and p95 latency |
| `summary.csv` | per mode and topology: mean/sd/median set-up time, mean set-up KB, mean throughput per IH |
| `raw/*.json` | the JSON printed by each `sdp-client bench` |

The script prints the summary table at the end. Treat the numbers as **local measurements** of this implementation on your hardware; they are not, and should not be presented as, the paper's results.

## Example local run

One full run (`./scripts/bench/run.sh`, commit `6957eeb`, 2026-11-13) on a laptop with an AMD Ryzen 5 5500U (6 cores / 12 threads), 22 GB RAM, Linux 7.0, Docker 29.7. **Local measurements of this implementation, not the paper's results**; your numbers will differ.

| Mode | Topology | Set-up time, mean (median) ms | of which: token | controller SPA | session request | AH SPA | first request | Set-up bytes (KB) | Requests / 10 min per IH | Failed |
|---|---|---|---|---|---|---|---|---|---|---|
| traditional | 1 (1 IH, 1 AH) | 281 (297) | — | 100 | 62 | 116 | 3 | 10.4 | 5930 | 0 |
| proposed | 1 | 317 (313) | 66 | 61 | 71 | 116 | 3 | 18.4 | 5930 | 0 |
| traditional | 2 (1 IH, 2 AHs) | 277 (283) | — | 98 | 60 | 116 | 3 | 15.7 | 5930 | 0 |
| proposed | 2 | 287 (286) | 52 | 51 | 66 | 115 | 3 | 24.6 | 5930 | 0 |
| traditional | 3 (1 IH, 5 AHs) | 246 (248) | — | 66 | 59 | 116 | 4 | 31.8 | 5930 | 0 |
| proposed | 3 | 344 (349) | 59 | 95 | 68 | 118 | 5 | 43.3 | 5930 | 0 |
| traditional | 4 (5 IHs, 10 AHs) | 319 (249) | — | 65 | 68 | 181 | 7 | 58.5 | 5930 | 0 |
| proposed | 4 | 403 (339) | 61 | 76 | 80 | 180 | 8 | 74.5 | 5930 | 0 |

How to read it:

- **What the IAM costs.** The Keycloak login (password + TOTP, one HTTPS round trip including the TLS handshake) takes 52–66 ms, and validating the token at the controller (signature, introspection, RBAC) adds about 5–12 ms to the session request. That is the overhead the proposed architecture adds to each set-up in this lab, of the same order as the 75–100 ms reported in the paper.
- **Why the totals are noisier than that.** Both SPA phases are dominated by fwknopd noticing the packet and inserting the rule; the controller phase varies between about 50 and 100 ms from run to run, which is as large as the IAM cost. Compare the phases rather than the totals, or raise `--runs`.
- **Topology 4 outliers.** With 5 IHs requesting sessions at the same moment, every AH reloads fwknopd several times in a row; a knock that arrives during a reload is occasionally lost and the client re-sends it after 1.5 s (maximum set-up 1.7–2.0 s, which inflates the means; the medians are unaffected).
- **Bytes.** Counted on the client's sockets (TLS records with certificates and handshakes), so they grow with the number of AHs (one mTLS connection and one SPA packet per AH). The proposed mode adds about 8 KB: the HTTPS token request (about 6.3 KB with its TLS handshake) and the token carried in the session request and in the first request to each AH.
- **Throughput.** The closed-loop workload (1 worker, 100 ms think time, ~1 ms latency per request) is limited by its think time, so it reaches the same 5930 requests per 10 minutes in both modes and all topologies: the per-request token check at the AH (cached validation) does not change it. Without think time or with more workers the benchmark would measure the capacity of this host instead; in proposed mode such traffic is exactly what the IDS is built to flag.
- The IDS was active during the proposed-mode runs and raised no alert on this workload.
