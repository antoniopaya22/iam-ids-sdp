# Contributing

Thanks for your interest in iam-ids-sdp.

1. Open an issue first for anything larger than a small fix, so the design can be discussed.
2. Keep the code dependency-light (Go standard library first; pinned Python dependencies for the IDS) and covered by tests.
3. Before opening a pull request, run:

   ```bash
   gofmt -l .                     # must print nothing
   go vet ./...
   go test -race ./...
   (cd ids && python -m pytest -q)
   ./scripts/gen-env.sh && docker compose up -d --build --wait && ./scripts/demo.sh
   ```

4. Keep `internal/gateway/features.go` and `ids/sdp_ids/features.py` in sync (a test checks it). If you change the telemetry, record a new dataset with `scripts/ids/record-dataset.sh`.
5. Update the documentation in `docs/` when behaviour or configuration changes (`mkdocs build --strict` with `requirements-docs.txt`).
6. Results quoted from the paper must stay labelled "as reported in the paper"; numbers measured with this code must say how they were measured.
7. Do not commit keys, certificates, `.env` or real credentials. Do not add attack tooling: the repository is limited to identity, authorization, monitoring and benchmarking.

Security issues: see [SECURITY.md](SECURITY.md).
