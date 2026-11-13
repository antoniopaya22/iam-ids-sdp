# IAM: realm, MFA and RBAC

In the proposed architecture the initiating host must obtain a session token from the identity provider **before** it may talk to the controller, and the token carries the roles that decide what the user may reach (paper, Sect. 5.3–5.4). The lab uses Keycloak, as the paper does.

## Keycloak in the lab

- Image `quay.io/keycloak/keycloak:26.8.1`, started with `start --import-realm` (production mode, HTTPS only, certificate from the lab PKI, hostname `https://keycloak:8443`).
- The realm is imported from [`keycloak/realm-sdp.json`](https://github.com/antoniopaya22/iam-ids-sdp/blob/main/keycloak/realm-sdp.json) every time the container is created. Passwords, TOTP secrets and the controller's client secret are placeholders (`${ALICE_PASSWORD}`, ...) that Keycloak fills from the container's environment, i.e. from `.env`; nothing secret is in the repository.
- Keycloak is on the public network (IHs must reach it before any SPA) and on the internal network (controller and gateways fetch its keys there).
- Its database is the embedded development store inside the container: recreating the container resets the realm.

## Realm `sdp`

| Item | Configuration |
|---|---|
| Roles | `admin` (every service), `researcher` (records + portal), `viewer` (portal), as in the paper's healthcare example |
| Users | `alice` (researcher), `bob` (viewer), `carol` (admin), `bench` (viewer, benchmark only); each with a password and an OTP credential |
| Client `sdp-client` | public client used by the IHs; direct access grant (password + `totp` parameter); audience mappers add `sdp-controller` and `sdp-gateway` to the access token |
| Client `sdp-controller` | confidential client with a service account holding `realm-management` roles `view-users` and `manage-users`, and the `kc-admin-api` client scope that Keycloak 26.8.2+ requires on Admin REST API tokens: token introspection and logging users out |
| Access token lifetime | 5 minutes |
| OTP policy | TOTP, HMAC-SHA1, 6 digits, 30 s period; codes reusable within their period (lab shortcut, see below) |
| Brute-force protection | on (10 failures) |

A token issued to alice looks like this (abridged):

```json
{
  "iss": "https://keycloak:8443/realms/sdp",
  "aud": ["sdp-gateway", "sdp-controller"],
  "sub": "4c3c4d7a-...", "sid": "ix1wYtR-...", "typ": "Bearer", "azp": "sdp-client",
  "exp": 1794567394, "iat": 1794567094,
  "realm_access": { "roles": ["researcher"] },
  "preferred_username": "alice"
}
```

## Multi-factor authentication

The lab uses Keycloak's direct grant flow, whose OTP step is required for users who have an OTP credential, so Keycloak checks both factors:

```text
$ docker compose exec ih-alice sdp-client login --no-otp
login refused: token endpoint: 400 Bad Request: invalid_grant (Invalid user credentials)

$ docker compose exec ih-alice sdp-client login
logged in as alice  realm roles [researcher]  aud [sdp-gateway sdp-controller]  expires ...
```

The paper mentions TOTP, hardware tokens or push notifications depending on the organisation; the lab implements TOTP. An interactive initiating host would use the authorization code flow with PKCE in a browser instead of the direct grant.

!!! warning "Demo OTP secrets (lab only)"
    The realm import gives every demo user an OTP credential with a known secret, and the same secret is passed to that user's client container (`SDP_OTP_SECRET`) so the scripts can compute the code that an authenticator app would display. `otpPolicyCodeReusable` is enabled so that repeated logins within 30 seconds (benchmark) work. In a real deployment users enrol their own authenticator and codes are single-use.

## Token validation

Both the controller and every accepting host validate the token offline against the realm's JWKS (`internal/iam`):

| Check | Controller | Accepting host |
|---|---|---|
| Signature (RS256/ES256 only; `none` and HMAC rejected), key looked up by `kid`, key rotation handled | yes | yes |
| `iss` = realm URL from OIDC discovery | yes | yes |
| `aud` contains | `sdp-controller` | `sdp-gateway` |
| `exp` required and not passed (5 s leeway), `iat` not in the future | yes | yes |
| `typ` = `Bearer` (ID tokens rejected), `azp` = `sdp-client`, `sub` present | yes | yes |
| Online introspection (still active in Keycloak?) | yes (`SDP_INTROSPECT`) | no (cached until `exp`; revoked `sid`s are refused) |
| Token user owns the device (certificate CN → `owner`) | yes | the token's `sub` must be the session's user |
| Realm role grants the service | yes | yes, for every request path |

Unit tests in `internal/iam/iam_test.go` cover valid tokens and rejections (expired, missing `exp`, wrong issuer, wrong audience, ID token, other client, no subject, issued in the future, bad signature, `alg: none`, HS256 signed with the public key, garbage), tokens without roles, key rotation, EC keys, the validation cache and TOTP test vectors from RFC 6238.

## RBAC mapping

`config/policy.yaml` maps realm roles to services; the controller decides at session time and the AH re-checks per request:

| | portal | records | admin |
|---|---|---|---|
| `viewer` (bob) | ✔ | ✘ 403 at the controller | ✘ |
| `researcher` (alice) | ✔ | ✔ | ✘ |
| `admin` (carol) | ✔ | ✔ | ✔ |

A session is granted for one service; a request for another path on the same session is refused by the AH (403), whatever the roles.

## Revocation in Keycloak

When the IDS raises an alert (or an administrator runs `sdp-controller revoke -user NAME -logout`), the controller calls `POST /admin/realms/sdp/users/{id}/logout` with its service account. This ends all of the user's SSO sessions in Keycloak, so refresh tokens stop working, introspection reports existing access tokens as inactive and the user has to authenticate again with both factors. Access tokens are self-contained, so the AHs additionally refuse the revoked Keycloak session id (`sid`) until the token expires. The audit log records the call as `iam_logout` with outcome `revoke` (or `error`).
