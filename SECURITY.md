# Security Policy

iam-ids-sdp is research software that implements the architecture of a published article. It has not been audited and is not intended for production use without your own review.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the **Security** tab of this repository and click **Report a vulnerability**. Do not open a public issue.

Include the affected component (`sdp-controller`, `sdp-gateway`, `sdp-client`, IDS, PKI tooling, Keycloak realm or lab configuration), the version or commit, steps to reproduce and the impact you observed.

## Scope

- Go code, IDS code, lab configuration and scripts of this repository: in scope.
- Keycloak: report to the [Keycloak project](https://github.com/keycloak/keycloak/security).
- fwknop: report to its maintainers ([mrash/fwknop](https://github.com/mrash/fwknop)) and to Debian if it concerns the packages.
- Apollon: report in [antoniopaya22/apollon](https://github.com/antoniopaya22/apollon).

## Lab shortcuts (by design, not vulnerabilities)

- The demo users' passwords and TOTP secrets are generated into the git-ignored `.env`, imported into Keycloak and given to the client containers so the scripts can log in; TOTP codes may be reused within their 30-second period. A real deployment enrols each user's own authenticator and uses single-use codes.
- Every gateway replica shares one certificate so that `docker compose --scale` works.
- The lab CA, keys and certificates are generated at start-up inside a Docker volume; never commit keys, certificates or `.env` (they are git-ignored).
