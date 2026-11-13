package gateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/audit"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/policy"
	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

const testPolicy = `
services:
  portal:  {path: /portal/,  roles: [viewer, researcher, admin]}
  records: {path: /records/, roles: [researcher, admin]}
devices:
  ih-alice: {owner: alice, services: [portal, records]}
`

type fakeSPA struct {
	mu      sync.Mutex
	stanzas map[string]spa.Stanza
}

func (f *fakeSPA) Set(_ context.Context, ss ...spa.Stanza) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range ss {
		if err := s.Validate(); err != nil {
			return err
		}
		f.stanzas[s.ID] = s
	}
	return nil
}

func (f *fakeSPA) Remove(_ context.Context, ids ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		delete(f.stanzas, id)
	}
	return nil
}

type fakeFW struct{ removed []string }

func (f *fakeFW) RemoveRulesFor(_ context.Context, ip string) (int, error) {
	f.removed = append(f.removed, ip)
	return 1, nil
}

type fakeValidator map[string]*iam.Claims

func (f fakeValidator) Validate(_ context.Context, raw string) (*iam.Claims, error) {
	if raw == "" {
		return nil, iam.ErrNoToken
	}
	if c, ok := f[raw]; ok {
		return c, nil
	}
	return nil, iam.ErrInvalidToken
}

func claims(user, sub, sid string, roles ...string) *iam.Claims {
	c := &iam.Claims{PreferredUsername: user, SessionID: sid}
	c.Subject = sub
	c.RealmAccess.Roles = roles
	return c
}

type harness struct {
	agent    *Agent
	spa      *fakeSPA
	fw       *fakeFW
	upstream *httptest.Server
	hits     int
	now      time.Time
}

func newHarness(t *testing.T, mode string) *harness {
	t.Helper()
	p, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{spa: &fakeSPA{stanzas: map[string]spa.Stanza{}}, fw: &fakeFW{}, now: time.Now()}
	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits++
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization header leaked to the protected service")
		}
		_, _ = w.Write([]byte("ok " + r.Header.Get("X-SDP-User")))
	}))
	t.Cleanup(h.upstream.Close)
	u, _ := url.Parse(h.upstream.URL)
	a, err := New(Config{
		ID: "gw-test", Mode: mode, Policy: p, Upstream: u, SPA: h.spa, Firewall: h.fw,
		Validator: fakeValidator{
			"tok-alice":    claims("alice", "u-alice", "sid-1", "researcher"),
			"tok-alice-vw": claims("alice", "u-alice", "sid-2", "viewer"),
			"tok-mallory":  claims("mallory", "u-mallory", "sid-3", "admin"),
		},
		Audit: audit.NewWriter("gateway", &bytes.Buffer{}),
		PeerFunc: func(r *http.Request) (tlsutil.Peer, error) {
			return tlsutil.Peer{ID: r.Header.Get("X-Test-CN"), Role: r.Header.Get("X-Test-OU")}, nil
		},
		Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.agent = a
	return h
}

func (h *harness) install(t *testing.T, mode, id, ip, subject string, services ...string) {
	t.Helper()
	k, hm := spa.NewKeys()
	err := h.agent.Install(context.Background(), api.GatewaySession{
		SessionID: id, Mode: mode, Device: "ih-alice", Subject: subject, Username: "alice", TokenSID: "sid-1",
		ClientIP: ip, Services: services, ServicePort: 8443, KeyBase64: k, HMACKeyBase64: hm,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (h *harness) get(path, ip, device, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("X-Test-CN", device)
	req.Header.Set("X-Test-OU", "device")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.agent.ServeHTTP(rec, req)
	return rec
}

func TestInstallRendersStanzaBoundToClient(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	st, ok := h.spa.stanzas["s1"]
	if !ok || st.Source != "10.233.0.40" || st.OpenPorts[0] != "tcp/8443" || st.AccessTimeout < 50 {
		t.Fatalf("stanza %+v", st)
	}
	out, err := spa.RenderAccessConf(h.agent.cfg.SPA.(*fakeSPA).list())
	if err != nil || !strings.Contains(out, "SOURCE                  10.233.0.40") {
		t.Fatalf("render: %v\n%s", err, out)
	}
	// Mode mismatch and expired sessions are refused.
	k, hm := spa.NewKeys()
	if err := h.agent.Install(context.Background(), api.GatewaySession{SessionID: "x", Mode: api.ModeProposed,
		ClientIP: "10.233.0.40", Services: []string{"portal"}, ServicePort: 8443, KeyBase64: k, HMACKeyBase64: hm,
		ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
		t.Fatal("mode mismatch accepted")
	}
	if err := h.agent.Install(context.Background(), api.GatewaySession{SessionID: "y", Mode: api.ModeTraditional,
		ClientIP: "10.233.0.40", Services: []string{"portal"}, ServicePort: 8443, KeyBase64: k, HMACKeyBase64: hm,
		ExpiresAt: time.Now().Add(-time.Second)}); err == nil {
		t.Fatal("expired session accepted")
	}
}

func (f *fakeSPA) list() []spa.Stanza {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []spa.Stanza
	for _, s := range f.stanzas {
		out = append(out, s)
	}
	return out
}

func TestTraditionalProxyChecksSessionAddressAndDevice(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	if rec := h.get("/portal/", "10.233.0.40", "ih-alice", ""); rec.Code != 200 {
		t.Fatalf("authorized request: %d %s", rec.Code, rec.Body)
	}
	if rec := h.get("/portal/", "10.233.0.99", "ih-alice", ""); rec.Code != 403 {
		t.Fatalf("other address: %d", rec.Code)
	}
	if rec := h.get("/portal/", "10.233.0.40", "ih-bob", ""); rec.Code != 403 {
		t.Fatalf("other device: %d", rec.Code)
	}
	if rec := h.get("/records/", "10.233.0.40", "ih-alice", ""); rec.Code != 403 {
		t.Fatalf("service not in session: %d", rec.Code)
	}
	if rec := h.get("/elsewhere", "10.233.0.40", "ih-alice", ""); rec.Code != 404 {
		t.Fatalf("unknown path: %d", rec.Code)
	}
	if h.hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", h.hits)
	}
}

func TestProposedProxyValidatesTokenIndependently(t *testing.T) {
	h := newHarness(t, api.ModeProposed)
	h.install(t, api.ModeProposed, "s1", "10.233.0.40", "u-alice", "portal", "records")
	cases := []struct {
		name, path, token string
		want              int
	}{
		{"no token", "/portal/", "", 401},
		{"forged token", "/portal/", "forged", 401},
		{"token of another identity", "/portal/", "tok-mallory", 403},
		{"role does not grant records", "/records/", "tok-alice-vw", 403},
		{"valid", "/records/", "tok-alice", 200},
	}
	for _, c := range cases {
		if rec := h.get(c.path, "10.233.0.40", "ih-alice", c.token); rec.Code != c.want {
			t.Errorf("%s: got %d (%s), want %d", c.name, rec.Code, strings.TrimSpace(rec.Body.String()), c.want)
		}
	}
	if rec := h.get("/records/", "10.233.0.40", "ih-alice", "tok-alice"); !strings.Contains(rec.Body.String(), "ok alice") {
		t.Fatalf("identity header not forwarded: %q", rec.Body)
	}
}

func TestRevokeStopsAccessAndCleansUp(t *testing.T) {
	h := newHarness(t, api.ModeProposed)
	h.install(t, api.ModeProposed, "s1", "10.233.0.40", "u-alice", "portal")
	if rec := h.get("/portal/", "10.233.0.40", "ih-alice", "tok-alice"); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	// Control API only accepts the controller.
	req := httptest.NewRequest("POST", "/v1/revoke", strings.NewReader(`{"session_id":"s1"}`))
	req.Header.Set("X-Test-OU", "device")
	rec := httptest.NewRecorder()
	h.agent.ControlHandler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("device revoked a session: %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "/v1/revoke", strings.NewReader(`{"session_id":"s1","token_sid":"sid-1","reason":"ids"}`))
	req.Header.Set("X-Test-OU", "controller")
	rec = httptest.NewRecorder()
	h.agent.ControlHandler().ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if _, ok := h.spa.stanzas["s1"]; ok {
		t.Fatal("stanza still present")
	}
	if len(h.fw.removed) != 1 || h.fw.removed[0] != "10.233.0.40" {
		t.Fatalf("firewall cleanup %v", h.fw.removed)
	}
	if rec := h.get("/portal/", "10.233.0.40", "ih-alice", "tok-alice"); rec.Code != 401 {
		t.Fatalf("revoked token still accepted: %d", rec.Code)
	}
	// A new session for the same user with a new IdP session works again.
	h.install(t, api.ModeProposed, "s2", "10.233.0.40", "u-alice", "portal")
	if rec := h.get("/portal/", "10.233.0.40", "ih-alice", "tok-alice-vw"); rec.Code != 200 {
		t.Fatalf("new session after revocation: %d", rec.Code)
	}
}

func TestRevokeKeepsRulesWhileAnotherSessionOfTheAddressLives(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	h.install(t, api.ModeTraditional, "s2", "10.233.0.40", "", "portal")
	h.agent.Revoke(context.Background(), api.RevokeRequest{SessionID: "s1"})
	if len(h.fw.removed) != 0 {
		t.Fatal("rules removed although s2 is alive")
	}
	if rec := h.get("/portal/", "10.233.0.40", "ih-alice", ""); rec.Code != 200 {
		t.Fatalf("s2 should still work: %d", rec.Code)
	}
}

func TestExpire(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	h.now = h.now.Add(2 * time.Minute)
	h.agent.Expire(context.Background())
	if _, ok := h.spa.stanzas["s1"]; ok || len(h.fw.removed) != 1 {
		t.Fatal("expired session not cleaned up")
	}
}

func TestSnapshotFeatures(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	h.agent.mu.Lock()
	h.agent.windowStart = h.now
	h.agent.mu.Unlock()
	for i := 0; i < 10; i++ {
		h.now = h.now.Add(100 * time.Millisecond)
		h.get("/portal/", "10.233.0.40", "ih-alice", "")
	}
	h.get("/records/", "10.233.0.40", "ih-alice", "") // denied: no stats, no session match
	h.now = h.now.Add(time.Second)                    // window of 2 s
	b := h.agent.Snapshot()
	if b.FeatureSet != api.FeatureSet || len(b.Windows) != 1 {
		t.Fatalf("batch %+v", b)
	}
	w := b.Windows[0]
	f := w.Features
	if len(f) != len(FeatureNames) {
		t.Fatalf("features %v", f)
	}
	for _, n := range FeatureNames {
		if _, ok := f[n]; !ok {
			t.Errorf("missing feature %s", n)
		}
	}
	if f["req_rate"] != 5 || f["distinct_paths"] != 1 || f["err_ratio"] != 0 {
		t.Errorf("req_rate=%v distinct=%v err=%v", f["req_rate"], f["distinct_paths"], f["err_ratio"])
	}
	if d := f["mean_iat_ms"] - 100; d > 0.01 || d < -0.01 || f["iat_cv"] > 0.01 {
		t.Errorf("iat mean=%v cv=%v", f["mean_iat_ms"], f["iat_cv"])
	}
	if f["bytes_out_rate"] <= 0 || f["bytes_in_rate"] <= 0 {
		t.Errorf("bytes %v %v", f["bytes_in_rate"], f["bytes_out_rate"])
	}
	// Idle sessions produce no window.
	h.now = h.now.Add(2 * time.Second)
	if b := h.agent.Snapshot(); len(b.Windows) != 0 {
		t.Fatalf("idle window exported: %+v", b.Windows)
	}
}

func TestStalledConnections(t *testing.T) {
	h := newHarness(t, api.ModeTraditional)
	h.install(t, api.ModeTraditional, "s1", "10.233.0.40", "", "portal")
	h.agent.mu.Lock()
	for i := 0; i < 5; i++ {
		h.agent.conns[fakeConn(i)] = &connInfo{ip: "10.233.0.40", opened: h.now}
	}
	h.agent.mu.Unlock()
	h.now = h.now.Add(3 * time.Second)
	b := h.agent.Snapshot()
	if len(b.Windows) != 1 || b.Windows[0].Features["stalled_conns"] != 5 || b.Windows[0].Features["open_conns"] != 5 {
		t.Fatalf("stalled windows %+v", b.Windows)
	}
}

type fakeConnT struct {
	net.Conn
	id int
}

func fakeConn(i int) net.Conn { return &fakeConnT{id: i} }
