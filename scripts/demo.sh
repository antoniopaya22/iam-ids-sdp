#!/usr/bin/env bash
# End-to-end check of the iam-ids-sdp lab started with
#   ./scripts/gen-env.sh && docker compose up -d --build --wait
#
# Proposed mode (Keycloak + IDS):
#   1. before SPA the controller, the accepting host and the service are invisible;
#   2. MFA: password without the TOTP code is refused; password + TOTP gives a token
#      carrying the user's realm roles;
#   3. happy path: token -> SPA + mTLS to the controller -> SPA to the AH -> HTTP 200;
#   4. authorization tests: no token, wrong role, AH re-checks every request on its own;
#   5. monitoring: after a period of normal use, a short HTTP load test with `hey`
#      (far above the user's learnt baseline) makes the IDS raise an alert and the
#      controller revoke the session (gateway + Keycloak);
#   6. after a new MFA login the user gets access again.
# Traditional mode runs steps 1, 3 and shows that only the device key pair is checked.
#
# Usage: ./scripts/demo.sh [--quick]     Exit status is non-zero if any check fails.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1
BASELINE_SECS=$([ $QUICK -eq 1 ] && echo 12 || echo 20)
LOAD_SECS=$([ $QUICK -eq 1 ] && echo 8 || echo 10)
WEB_PRIVATE=10.233.1.30
CONTROLLER=10.233.0.10
PROXY_PORT=8080

failures=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }
info() { printf '  \033[36mINFO\033[0m %s\n' "$1"; }
check() { if [ "$1" -eq 0 ]; then pass "$2"; else fail "$3"; fi; } # <0=ok> <pass msg> <fail msg>
is() { [ "$1" = "$2" ]; echo $?; }
step() { printf '\n\033[1m[%s] %s\033[0m\n' "$1" "$2"; }
indent() { sed 's/^/    /'; }
ex() { docker compose exec -T "$@"; }
# tcp_dark <service> <ip> <port>: 0 if a TCP connection cannot be opened within 2 s
tcp_dark() { if ex "$1" timeout 2 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; then echo 1; else echo 0; fi; }
ctl() { ex controller sdp-controller "$@"; }
ids_status() { ex ids python -m sdp_ids status; }

cleanup() {
    for c in ih-alice ih-bob; do
        ex "$c" pkill -f 'sdp-client proxy' >/dev/null 2>&1 || true
        ex "$c" sdp-client disconnect >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

MODE="$(ctl status -json 2>/dev/null | grep -o '"mode":"[a-z]*"' | cut -d'"' -f4)"
if [ -z "$MODE" ]; then
    echo "The lab is not running: ./scripts/gen-env.sh && docker compose up -d --build --wait"
    exit 1
fi
GW=""
for _ in $(seq 1 30); do # gateways re-register within 10 s after a controller restart
    GW="$(ctl status -json | grep -o '"public_addr":"[0-9.]*"' | head -1 | cut -d'"' -f4)"
    [ -n "$GW" ] && break
    sleep 1
done
echo "Lab mode: $MODE   first accepting host: ${GW:-none}"
[ -n "$GW" ] || { echo "no accepting host registered"; exit 1; }

step 0 "Clean state: end the demo users' sessions left by earlier runs"
ctl revoke -device ih-alice -reason "demo reset" | indent
ctl revoke -device ih-bob -reason "demo reset" | indent
cleanup
sleep 6 # the controller's SPA door (5 s) closes again

step 1 "Before SPA: controller, accepting host and service are invisible"
check "$(tcp_dark ih-alice "$CONTROLLER" 8443)" "alice: controller tcp/8443 filtered" "controller port reachable without SPA"
check "$(tcp_dark ih-alice "$GW" 8443)" "alice: accepting host tcp/8443 filtered" "accepting host reachable without SPA"
check "$(tcp_dark ih-alice "$WEB_PRIVATE" 80)" "alice: protected nginx ($WEB_PRIVATE) unreachable" "private service reachable"

if [ "$MODE" = "proposed" ]; then
    step 2 "IAM: multi-factor authentication with Keycloak"
    out="$(ex ih-alice sdp-client login --no-otp 2>&1)"; rc=$?
    printf '%s\n' "$out" | indent
    check "$(is $rc 2)" "password without the TOTP code is refused" "login without TOTP returned rc=$rc"
    out="$(ex ih-alice sdp-client login 2>&1)"; rc=$?
    printf '%s\n' "$out" | indent
    [ $rc -eq 0 ] && grep -q "realm roles \[researcher\]" <<<"$out"
    check $? "password + TOTP: token for alice with realm role researcher" "login with TOTP failed (rc=$rc)"
fi

step 3 "Happy path: alice opens the portal"
out="$(ex ih-alice sdp-client connect portal 2>&1)"; rc=$?
printf '%s\n' "$out" | indent
[ $rc -eq 0 ] && grep -q "HTTP 200" <<<"$out"
check $? "MFA token -> SPA + mTLS controller -> SPA accepting host -> HTTP 200" "connect portal failed (rc=$rc)"
out="$(ex ih-alice sdp-client get /portal/ 2>&1)"; rc=$?
check "$(is $rc 0)" "alice: second request on the session -> ${out##* }" "second request failed: $out"
check "$(tcp_dark ih-bob "$GW" 8443)" "bob: accepting host still invisible to him" "bob reached the accepting host"

if [ "$MODE" = "traditional" ]; then
    step 4 "Traditional SDP: the device key pair is the only credential"
    out="$(ex ih-bob sdp-client connect records 2>&1)"; rc=$?
    printf '%s\n' "$out" | indent
    check "$(is $rc 0)" "bob's device reaches records: no user, role or MFA check (the gap the paper addresses)" "bob connect records rc=$rc"
    step 5 "Monitoring"
    info "skipped: traditional mode has no IAM context and no IDS"
else
    step 4 "Authorization tests"
    out="$(ex ih-alice sdp-client connect --no-login portal 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -i denied | indent
    check "$(is $rc 3)" "no token: the controller refuses the session (401) even with a valid device certificate" "no-token session returned rc=$rc"
    out="$(ex ih-bob sdp-client connect records 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -i denied | indent
    check "$(is $rc 3)" "wrong role: bob (viewer) is refused records (403)" "bob records returned rc=$rc"
    check "$(tcp_dark ih-bob "$GW" 8443)" "bob: accepting host stays invisible after the refusal" "bob reached the accepting host"
    out="$(ex ih-bob sdp-client connect portal 2>&1)"; rc=$?
    check "$(is $rc 0)" "bob (viewer) is granted the portal" "bob portal rc=$rc"
    out="$(ex ih-bob sdp-client get /admin/ 2>&1)"; rc=$?
    printf '%s\n' "$out" | indent
    [ $rc -eq 4 ] && grep -q "HTTP 403" <<<"$out"
    check $? "accepting host refuses /admin/ on bob's portal session (its own RBAC check)" "bob /admin/: rc=$rc"
    out="$(ex ih-alice sdp-client get --no-token /portal/ 2>&1)"; rc=$?
    printf '%s\n' "$out" | indent
    [ $rc -eq 4 ] && grep -q "HTTP 401" <<<"$out"
    check $? "accepting host refuses a request on alice's session without the token (independent validation)" "no-token request: rc=$rc"

    step 5 "Monitoring: IDS (Apollon MAB + per-identity baseline) and revocation"
    session="$(ex ih-alice jq -r .session.session_id /tmp/sdp-session.json)"
    ex -d ih-alice sh -c "exec sdp-client proxy --listen 127.0.0.1:$PROXY_PORT > /tmp/proxy.log 2>&1"
    sleep 1
    info "normal use for ${BASELINE_SECS}s through the local forwarder (about 1 request/s)"
    ex ih-alice sh -c "for i in \$(seq 1 $BASELINE_SECS); do curl -s -o /dev/null http://127.0.0.1:$PROXY_PORT/portal/; sleep 1; done"
    ids_status | grep -E "^baseline alice|^model|^policy" | indent
    info "short load test: hey -z ${LOAD_SECS}s -c 10 http://127.0.0.1:$PROXY_PORT/portal/"
    ex ih-alice hey -z "${LOAD_SECS}s" -c 10 "http://127.0.0.1:$PROXY_PORT/portal/" \
        | grep -E "Requests/sec|^\s+\[[0-9]+\]" | indent
    alert=""
    for _ in $(seq 1 20); do
        alert="$(ids_status | grep "^alert .*session $session")" && break
        sleep 1
    done
    printf '%s\n' "$alert" | indent
    got_alert=1
    [ -n "$alert" ] && got_alert=0
    check "$got_alert" "IDS raised an alert for alice's session $session" "no IDS alert for $session"
    grep -q "'action': 'revoked'" <<<"$alert"
    check $? "controller acknowledged the alert and revoked the session" "controller did not revoke"
    ctl status -sessions | grep "$session" | indent
    ctl status -sessions | grep "$session" | grep -q "revoked.*IDS alert"
    check $? "controller session state: revoked by the IDS alert" "session not revoked at the controller"
    ex controller grep '"event":"iam_logout"' /var/log/sdp/audit.jsonl | tail -1 | grep -q '"outcome":"revoke"'
    check $? "Keycloak session of alice ended (audit: iam_logout)" "no successful Keycloak logout in the audit log"
    out="$(ex ih-alice sdp-client get /portal/ 2>&1)"; rc=$?
    check "$(is $rc 4)" "alice's session no longer reaches the service" "alice still served after revocation: $out"
    check "$(tcp_dark ih-alice "$GW" 8443)" "accepting host is invisible to alice again" "accepting host still open for alice"
    out="$(ex ih-bob sdp-client get /portal/ 2>&1)"; rc=$?
    check "$(is $rc 0)" "bob's session is unaffected ($out)" "bob lost access: $out"
    ex ih-alice pkill -f 'sdp-client proxy' >/dev/null 2>&1

    step 6 "Recovery: a new MFA login gives alice a new session"
    out="$(ex ih-alice sdp-client connect portal 2>&1)"; rc=$?
    printf '%s\n' "$out" | tail -2 | indent
    check "$(is $rc 0)" "alice re-authenticated (password + TOTP) and reached the portal" "re-authentication failed (rc=$rc)"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "All checks passed."
else
    echo "$failures check(s) failed. Inspect: docker compose logs controller gateway ids keycloak"
    exit 1
fi
