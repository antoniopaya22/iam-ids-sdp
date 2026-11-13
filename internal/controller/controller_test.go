package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/audit"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/policy"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
	"github.com/golang-jwt/jwt/v5"
)

const testPolicy = `
services:
  portal:  {path: /portal/,  roles: [viewer, researcher, admin]}
  records: {path: /records/, roles: [researcher, admin]}
devices:
  ih-alice: {owner: alice, services: [portal, records]}
  ih-bob:   {owner: bob,   services: [portal, records]}
`

// fakeValidator accepts tokens named in the map.
type fakeValidator map[string]*iam.Claims

func (f fakeValidator) Validate(_ context.Context, raw string) (*iam.Claims, error) {
	if raw == "" {
		return nil, iam.ErrNoToken
	}
	c, ok := f[raw]
	if !ok {
		return nil, iam.ErrInvalidToken
	}
	return c, nil
}

func claims(user, sub, sid string, roles ...string) *iam.Claims {
	c := &iam.Claims{PreferredUsername: user, SessionID: sid}
	c.Subject = sub
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
	c.RealmAccess.Roles = roles
	return c
}

type fakeGateways struct {
	mu        sync.Mutex
	installed []api.GatewaySession
	revoked   []api.RevokeRequest
	fail      map[string]bool
}

func (f *fakeGateways) Install(_ context.Context, gw Gateway, s api.GatewaySession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[gw.ID] {
		return errors.New("unreachable")
	}
	f.installed = append(f.installed, s)
	return nil
}

func (f *fakeGateways) Revoke(_ context.Context, gw Gateway, r api.RevokeRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, r)
	return nil
}

type fakeIAM struct {
	mu       sync.Mutex
	inactive map[string]bool
	logouts  []string
}

func (f *fakeIAM) Introspect(_ context.Context, token string) (*iam.Introspection, error) {
	return &iam.Introspection{Active: !f.inactive[token]}, nil
}

func (f *fakeIAM) LogoutUser(_ context.Context, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logouts = append(f.logouts, sub)
	return nil
}

type harness struct {
	srv   *Server
	h     http.Handler
	gws   *fakeGateways
	iam   *fakeIAM
	audit *bytes.Buffer
	now   time.Time
}

func newHarness(t *testing.T, mode string) *harness {
	t.Helper()
	p, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	hs := &harness{gws: &fakeGateways{fail: map[string]bool{}}, iam: &fakeIAM{inactive: map[string]bool{}},
		audit: &bytes.Buffer{}, now: time.Now()}
	srv, err := New(Config{
		Mode: mode, Policy: p, SessionTTL: time.Minute, Introspect: true, IAM: hs.iam,
		Validator: fakeValidator{
			"tok-alice":   claims("alice", "u-alice", "sid-a1", "researcher"),
			"tok-alice-2": claims("alice", "u-alice", "sid-a2", "researcher"),
			"tok-bob":     claims("bob", "u-bob", "sid-b", "viewer"),
			"tok-noroles": claims("alice", "u-alice", "sid-a3"),
		},
		Gateways: hs.gws, Audit: audit.NewWriter("controller", hs.audit),
		// Tests identify the peer with headers instead of a TLS client certificate.
		PeerFunc: func(r *http.Request) (tlsutil.Peer, error) {
			return tlsutil.Peer{ID: r.Header.Get("X-Test-CN"), Role: r.Header.Get("X-Test-OU")}, nil
		},
		Now: func() time.Time { return hs.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	hs.srv, hs.h = srv, srv.Handler()
	for _, id := range []string{"gw-1", "gw-2"} {
		rec := hs.do(t, "POST", "/v1/gateways", "gateway", id, "", api.GatewayRegistration{
			ID: id, PublicAddr: "10.233.0.20", ControlURL: "https://" + id + ":9443", SPAPort: 62201, ProxyPort: 8080})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("register: %d %s", rec.Code, rec.Body)
		}
	}
	return hs
}

func (hs *harness) do(t *testing.T, method, path, role, cn, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "10.233.0.40:51000"
	req.Header.Set("X-Test-CN", cn)
	req.Header.Set("X-Test-OU", role)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func (hs *harness) session(t *testing.T, device, token, service string) (int, api.SessionResponse) {
	t.Helper()
	rec := hs.do(t, "POST", "/v1/sessions", "device", device, token, api.SessionRequest{Service: service})
	var resp api.SessionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

func TestTraditionalModeAuthorizesByKeyPairOnly(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	code, resp := hs.session(t, "ih-bob", "", "records")
	if code != http.StatusOK {
		t.Fatalf("traditional: bob's device should reach records, got %d", code)
	}
	if len(resp.Grants) != 2 || resp.Grants[0].KeyBase64 == resp.Grants[1].KeyBase64 {
		t.Fatalf("expected one grant per gateway with distinct keys: %+v", resp.Grants)
	}
	if resp.ClientIP != "10.233.0.40" || resp.Path != "/records/" {
		t.Fatalf("unexpected response %+v", resp)
	}
	if code, _ := hs.session(t, "ih-mallory", "", "portal"); code != http.StatusForbidden {
		t.Fatalf("unknown device: got %d", code)
	}
	if code, _ := hs.session(t, "ih-bob", "", "nope"); code != http.StatusNotFound {
		t.Fatalf("unknown service: got %d", code)
	}
}

func TestProposedModeRequiresValidTokenAndRole(t *testing.T) {
	hs := newHarness(t, api.ModeProposed)
	cases := []struct {
		name, device, token, service string
		want                         int
	}{
		{"no token (stolen key pair only)", "ih-alice", "", "portal", http.StatusUnauthorized},
		{"invalid token", "ih-alice", "forged", "portal", http.StatusUnauthorized},
		{"wrong role", "ih-bob", "tok-bob", "records", http.StatusForbidden},
		{"no roles claim", "ih-alice", "tok-noroles", "portal", http.StatusForbidden},
		{"token of another user", "ih-alice", "tok-bob", "portal", http.StatusForbidden},
		{"viewer to portal", "ih-bob", "tok-bob", "portal", http.StatusOK},
		{"researcher to records", "ih-alice", "tok-alice", "records", http.StatusOK},
	}
	for _, c := range cases {
		if code, _ := hs.session(t, c.device, c.token, c.service); code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, code, c.want)
		}
	}
	hs.iam.inactive["tok-alice"] = true
	if code, _ := hs.session(t, "ih-alice", "tok-alice", "portal"); code != http.StatusUnauthorized {
		t.Errorf("introspection inactive: got %d", code)
	}
	if !strings.Contains(hs.audit.String(), `"outcome":"deny"`) || !strings.Contains(hs.audit.String(), `"outcome":"allow"`) {
		t.Errorf("audit log incomplete:\n%s", hs.audit)
	}
}

func TestProposedSessionCarriesIdentityToGateways(t *testing.T) {
	hs := newHarness(t, api.ModeProposed)
	code, resp := hs.session(t, "ih-alice", "tok-alice", "records")
	if code != http.StatusOK {
		t.Fatal(code)
	}
	if len(hs.gws.installed) != 2 {
		t.Fatalf("installed on %d gateways", len(hs.gws.installed))
	}
	gs := hs.gws.installed[0]
	if gs.Subject != "u-alice" || gs.Username != "alice" || gs.TokenSID != "sid-a1" || gs.ClientIP != "10.233.0.40" ||
		gs.SessionID != resp.SessionID || len(gs.Roles) != 1 || gs.Services[0] != "records" {
		t.Fatalf("gateway session %+v", gs)
	}
	// Session lifetime is capped by the token expiry.
	if !resp.ExpiresAt.Before(hs.now.Add(time.Minute).Add(time.Second)) {
		t.Fatalf("expires %v", resp.ExpiresAt)
	}
}

func TestPartialGatewayFailure(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	hs.gws.fail["gw-2"] = true
	code, resp := hs.session(t, "ih-alice", "", "portal")
	if code != http.StatusOK || len(resp.Grants) != 1 || resp.Grants[0].GatewayID != "gw-1" {
		t.Fatalf("code %d grants %+v", code, resp.Grants)
	}
	hs.gws.fail["gw-1"] = true
	if code, _ := hs.session(t, "ih-alice", "", "portal"); code != http.StatusBadGateway {
		t.Fatalf("all gateways failing: got %d", code)
	}
}

func TestAlertRevokesSessionsOfTheIdentity(t *testing.T) {
	hs := newHarness(t, api.ModeProposed)
	_, s1 := hs.session(t, "ih-alice", "tok-alice", "records")
	_, s2 := hs.session(t, "ih-alice", "tok-alice-2", "portal") // same user, second session
	_, s3 := hs.session(t, "ih-bob", "tok-bob", "portal")       // someone else

	// Only the IDS may raise alerts.
	if rec := hs.do(t, "POST", "/v1/alerts", "device", "ih-alice", "", api.Alert{SessionID: s1.SessionID}); rec.Code != http.StatusForbidden {
		t.Fatalf("alert from a device accepted: %d", rec.Code)
	}

	rec := hs.do(t, "POST", "/v1/alerts", "ids", "ids", "", api.Alert{
		SessionID: s1.SessionID, Detector: "apollon-mab", Reason: "http flood", Score: 0.99})
	var ar api.AlertResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	if rec.Code != http.StatusOK || ar.Action != "revoked" || len(ar.Revoked) != 2 {
		t.Fatalf("alert: %d %+v", rec.Code, ar)
	}
	revokedIDs := map[string]bool{}
	for _, r := range hs.gws.revoked {
		revokedIDs[r.SessionID] = true
	}
	if !revokedIDs[s1.SessionID] || !revokedIDs[s2.SessionID] || revokedIDs[s3.SessionID] {
		t.Fatalf("revoked on gateways: %v", revokedIDs)
	}
	if len(hs.gws.revoked) != 4 { // 2 sessions x 2 gateways
		t.Fatalf("expected 4 gateway revocations, got %d", len(hs.gws.revoked))
	}
	if len(hs.iam.logouts) != 1 || hs.iam.logouts[0] != "u-alice" {
		t.Fatalf("keycloak logouts: %v", hs.iam.logouts)
	}
	st := hs.srv.Status(true)
	if st.ActiveSessions != 1 {
		t.Fatalf("active sessions after revocation: %d", st.ActiveSessions)
	}
	// A second alert for the same session is ignored.
	rec = hs.do(t, "POST", "/v1/alerts", "ids", "ids", "", api.Alert{SessionID: s1.SessionID})
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	if ar.Action != "ignored" {
		t.Fatalf("duplicate alert: %+v", ar)
	}
	for _, s := range st.Sessions {
		if s.KeyBase64 != "" {
			t.Fatal("status leaks SPA keys")
		}
	}
}

func TestAlertScopeSession(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	hs.srv.cfg.RevokeScope = "session"
	_, s1 := hs.session(t, "ih-alice", "", "portal")
	hs.session(t, "ih-alice", "", "portal")
	rec := hs.do(t, "POST", "/v1/alerts", "ids", "ids", "", api.Alert{SessionID: s1.SessionID})
	var ar api.AlertResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ar)
	if len(ar.Revoked) != 1 || len(hs.iam.logouts) != 0 {
		t.Fatalf("scope session: %+v, logouts %v", ar, hs.iam.logouts)
	}
}

func TestEndSessionOnlyByOwner(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	_, s := hs.session(t, "ih-alice", "", "portal")
	if rec := hs.do(t, "DELETE", "/v1/sessions/"+s.SessionID, "device", "ih-bob", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("other device ended the session: %d", rec.Code)
	}
	if rec := hs.do(t, "DELETE", "/v1/sessions/"+s.SessionID, "device", "ih-alice", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("owner could not end the session: %d", rec.Code)
	}
	if len(hs.gws.revoked) != 2 {
		t.Fatalf("gateway revocations: %d", len(hs.gws.revoked))
	}
}

func TestHousekeepExpiresSessionsAndGateways(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	hs.session(t, "ih-alice", "", "portal")
	hs.now = hs.now.Add(2 * time.Minute)
	hs.srv.Housekeep(context.Background())
	if st := hs.srv.Status(false); st.ActiveSessions != 0 || len(st.Gateways) != 0 {
		t.Fatalf("after housekeeping: %+v", st)
	}
	if len(hs.gws.revoked) != 2 || hs.gws.revoked[0].Reason != "session lifetime reached" {
		t.Fatalf("expiry revocations: %+v", hs.gws.revoked)
	}
	if code, _ := hs.session(t, "ih-alice", "", "portal"); code != http.StatusServiceUnavailable {
		t.Fatalf("no gateways left: got %d", code)
	}
}

func TestRegistrationValidation(t *testing.T) {
	hs := newHarness(t, api.ModeTraditional)
	bad := []api.GatewayRegistration{
		{ID: "", PublicAddr: "10.0.0.1", ControlURL: "https://x", SPAPort: 1, ProxyPort: 1},
		{ID: "g", PublicAddr: "nope", ControlURL: "https://x", SPAPort: 1, ProxyPort: 1},
		{ID: "g", PublicAddr: "10.0.0.1", ControlURL: "http://x", SPAPort: 1, ProxyPort: 1},
	}
	for _, b := range bad {
		if rec := hs.do(t, "POST", "/v1/gateways", "gateway", "g", "", b); rec.Code != http.StatusBadRequest {
			t.Errorf("%+v accepted: %d", b, rec.Code)
		}
	}
	if rec := hs.do(t, "POST", "/v1/gateways", "device", "ih-alice", "", bad[0]); rec.Code != http.StatusForbidden {
		t.Errorf("device registered a gateway: %d", rec.Code)
	}
}
