// Package gateway implements the SDP Accepting Host (AH).
//
// The AH keeps every port closed (default-drop firewall). For each session the controller
// pushes, it adds an fwknop access stanza with per-session SPA keys bound to the IH
// address; a valid SPA packet then opens the reverse-proxy port for that address only.
//
// The reverse proxy terminates mutual TLS (device certificate) and, in proposed mode,
// independently validates the IH's Keycloak token (JWKS signature, issuer, audience,
// expiry), checks that it belongs to the session the controller announced and that its
// roles grant the requested service (its own copy of the RBAC policy). It also records
// per-session traffic features and exports them to the IDS every window.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/audit"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/policy"
	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

// SPA is the subset of spa.Daemon the agent needs.
type SPA interface {
	Set(ctx context.Context, stanzas ...spa.Stanza) error
	Remove(ctx context.Context, ids ...string) error
}

// RuleRemover drops the firewall rules and tracked connections of an address.
type RuleRemover interface {
	RemoveRulesFor(ctx context.Context, ip string) (int, error)
}

// TokenValidator validates bearer tokens (iam.CachingValidator in production).
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*iam.Claims, error)
}

// TelemetrySink receives a batch every window (the IDS client in production).
type TelemetrySink func(ctx context.Context, batch api.TelemetryBatch) error

// Config of the agent.
type Config struct {
	ID             string
	Mode           string
	Policy         *policy.Policy
	Upstream       *url.URL
	SPA            SPA
	Firewall       RuleRemover
	Validator      TokenValidator // proposed mode
	Telemetry      TelemetrySink  // proposed mode; nil disables export
	Window         time.Duration
	StallThreshold time.Duration // a connection without a complete request for this long is "stalled"
	Audit          *audit.Log
	Logger         *log.Logger
	PeerFunc       func(*http.Request) (tlsutil.Peer, error)
	Now            func() time.Time
}

type session struct {
	api.GatewaySession
	revoked bool
	stats   *windowStats
}

// Agent is the AH.
type Agent struct {
	cfg   Config
	proxy *httputil.ReverseProxy

	mu          sync.Mutex
	sessions    map[string]*session
	revokedSIDs map[string]time.Time
	conns       map[net.Conn]*connInfo
	windowStart time.Time
}

// New returns an agent.
func New(cfg Config) (*Agent, error) {
	if cfg.Mode != api.ModeTraditional && cfg.Mode != api.ModeProposed {
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if cfg.Mode == api.ModeProposed && cfg.Validator == nil {
		return nil, errors.New("proposed mode needs a token validator")
	}
	if cfg.Policy == nil || cfg.Upstream == nil || cfg.SPA == nil || cfg.Firewall == nil || cfg.Audit == nil {
		return nil, errors.New("policy, upstream, spa, firewall and audit are required")
	}
	if cfg.Window == 0 {
		cfg.Window = 2 * time.Second
	}
	if cfg.StallThreshold == 0 {
		cfg.StallThreshold = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.PeerFunc == nil {
		cfg.PeerFunc = func(r *http.Request) (tlsutil.Peer, error) { return tlsutil.PeerOf(r.TLS) }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Agent{cfg: cfg, sessions: map[string]*session{}, revokedSIDs: map[string]time.Time{},
		conns: map[net.Conn]*connInfo{}, windowStart: cfg.Now()}
	a.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			pr.SetXForwarded()
			pr.Out.Header.Del("Authorization") // minimal disclosure: the service gets identity headers only
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logger.Printf("upstream error: %v", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return a, nil
}

// ---------------------------------------------------------------- control API (controller -> AH)

// ControlHandler is the mTLS API the controller uses to install and revoke sessions.
func (a *Agent) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", a.onlyController(a.handleInstall))
	mux.HandleFunc("POST /v1/revoke", a.onlyController(a.handleRevoke))
	return mux
}

func (a *Agent) onlyController(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.cfg.PeerFunc(r)
		if err != nil || p.Role != api.OUController {
			http.Error(w, "controller certificate required", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (a *Agent) handleInstall(w http.ResponseWriter, r *http.Request) {
	var gs api.GatewaySession
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&gs); err != nil {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	if err := a.Install(r.Context(), gs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Agent) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var rr api.RevokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rr); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	a.Revoke(r.Context(), rr)
	w.WriteHeader(http.StatusNoContent)
}

// Install adds a session: an SPA stanza bound to the IH address that opens the proxy port.
func (a *Agent) Install(ctx context.Context, gs api.GatewaySession) error {
	if net.ParseIP(gs.ClientIP) == nil || gs.SessionID == "" || len(gs.Services) == 0 {
		return errors.New("session needs id, client ip and services")
	}
	if gs.Mode != a.cfg.Mode {
		return fmt.Errorf("mode mismatch: controller %s, gateway %s", gs.Mode, a.cfg.Mode)
	}
	if a.cfg.Mode == api.ModeProposed && gs.Subject == "" {
		return errors.New("proposed mode session without subject")
	}
	ttl := int(time.Until(gs.ExpiresAt).Seconds())
	if ttl < 1 {
		return errors.New("session already expired")
	}
	st := spa.Stanza{ID: gs.SessionID, Source: gs.ClientIP, OpenPorts: []string{fmt.Sprintf("tcp/%d", gs.ServicePort)},
		KeyBase64: gs.KeyBase64, HMACKeyBase64: gs.HMACKeyBase64, AccessTimeout: ttl}
	if err := a.cfg.SPA.Set(ctx, st); err != nil {
		return fmt.Errorf("spa: %w", err)
	}
	a.mu.Lock()
	gs.KeyBase64, gs.HMACKeyBase64 = "", ""
	a.sessions[gs.SessionID] = &session{GatewaySession: gs, stats: newWindowStats()}
	a.mu.Unlock()
	a.cfg.Audit.Record(audit.Event{Event: "session_installed", Outcome: "allow", Mode: a.cfg.Mode,
		SessionID: gs.SessionID, Device: gs.Device, Username: gs.Username, Subject: gs.Subject,
		ClientIP: gs.ClientIP, Gateway: a.cfg.ID, Service: strings.Join(gs.Services, ",")})
	return nil
}

// Revoke tears a session down: no more SPA with its keys, its token is refused, and (if
// the address has no other live session) its firewall rules and connections are dropped.
func (a *Agent) Revoke(ctx context.Context, rr api.RevokeRequest) {
	a.mu.Lock()
	s, ok := a.sessions[rr.SessionID]
	if ok {
		s.revoked = true
	}
	if rr.TokenSID != "" {
		a.revokedSIDs[rr.TokenSID] = a.cfg.Now()
	}
	ip := rr.ClientIP
	if ok {
		ip = s.ClientIP
	}
	others := a.liveSessionsForIPLocked(ip)
	var toClose []net.Conn
	if others == 0 {
		for c, ci := range a.conns {
			if ci.ip == ip {
				toClose = append(toClose, c)
			}
		}
	}
	a.mu.Unlock()

	if err := a.cfg.SPA.Remove(ctx, rr.SessionID); err != nil {
		a.cfg.Logger.Printf("revoke %s: spa: %v", rr.SessionID, err)
	}
	removed := 0
	if others == 0 && ip != "" {
		n, err := a.cfg.Firewall.RemoveRulesFor(ctx, ip)
		if err != nil {
			a.cfg.Logger.Printf("revoke %s: firewall: %v", rr.SessionID, err)
		}
		removed = n
	}
	for _, c := range toClose {
		_ = c.Close()
	}
	a.cfg.Audit.Record(audit.Event{Event: "session_revoked", Outcome: "revoke", Mode: a.cfg.Mode,
		SessionID: rr.SessionID, ClientIP: ip, Gateway: a.cfg.ID, Reason: rr.Reason,
		Detail: map[string]any{"firewall_rules_removed": removed, "connections_closed": len(toClose), "other_live_sessions": others}})
}

func (a *Agent) liveSessionsForIPLocked(ip string) int {
	n := 0
	now := a.cfg.Now()
	for _, s := range a.sessions {
		if s.ClientIP == ip && !s.revoked && now.Before(s.ExpiresAt) {
			n++
		}
	}
	return n
}

// Expire revokes sessions whose lifetime is over; run it periodically.
func (a *Agent) Expire(ctx context.Context) {
	now := a.cfg.Now()
	var ids []api.RevokeRequest
	a.mu.Lock()
	for id, s := range a.sessions {
		if !s.revoked && now.After(s.ExpiresAt) {
			ids = append(ids, api.RevokeRequest{SessionID: id, ClientIP: s.ClientIP, Reason: "expired"})
		}
		if s.revoked && now.Sub(s.ExpiresAt) > 10*time.Minute {
			delete(a.sessions, id)
		}
	}
	for sid, t := range a.revokedSIDs {
		if now.Sub(t) > time.Hour {
			delete(a.revokedSIDs, sid)
		}
	}
	a.mu.Unlock()
	for _, rr := range ids {
		a.Revoke(ctx, rr)
	}
}

// ---------------------------------------------------------------- data plane (IH -> AH -> service)

// decision is the outcome of the per-request access check.
type decision struct {
	status  int
	reason  string
	session *session
	service string
}

// authorize implements the AH's own policy enforcement for one request.
func (a *Agent) authorize(r *http.Request) decision {
	ip := remoteIP(r)
	peer, err := a.cfg.PeerFunc(r)
	if err != nil || peer.Role != api.OUDevice {
		return decision{status: http.StatusForbidden, reason: "device certificate required"}
	}
	service, ok := a.cfg.Policy.ServiceForPath(r.URL.Path)
	if !ok {
		return decision{status: http.StatusNotFound, reason: "no service at " + r.URL.Path}
	}

	var claims *iam.Claims
	if a.cfg.Mode == api.ModeProposed {
		raw := bearer(r)
		claims, err = a.cfg.Validator.Validate(r.Context(), raw)
		if err != nil {
			return decision{status: http.StatusUnauthorized, reason: "token rejected: " + err.Error()}
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if claims != nil && claims.SessionID != "" {
		if _, revoked := a.revokedSIDs[claims.SessionID]; revoked {
			return decision{status: http.StatusUnauthorized, reason: "token belongs to a revoked session"}
		}
	}
	now := a.cfg.Now()
	var match *session
	for _, s := range a.sessions {
		if s.revoked || s.ClientIP != ip || s.Device != peer.ID || !now.Before(s.ExpiresAt) {
			continue
		}
		if claims != nil && s.Subject != claims.Subject {
			continue
		}
		if !containsStr(s.Services, service) {
			continue
		}
		if match == nil || s.ExpiresAt.After(match.ExpiresAt) {
			match = s
		}
	}
	if match == nil {
		return decision{status: http.StatusForbidden, reason: fmt.Sprintf("no live session for %s/%s grants %s", ip, peer.ID, service)}
	}
	if claims != nil && !a.cfg.Policy.RolesAllow(claims.Roles(), service) {
		return decision{status: http.StatusForbidden, session: match,
			reason: fmt.Sprintf("roles %v do not grant %s", claims.Roles(), service)}
	}
	return decision{status: http.StatusOK, session: match, service: service}
}

// ServeHTTP is the reverse proxy in front of the protected service.
func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := a.cfg.Now()
	d := a.authorize(r)
	cw := &countingWriter{ResponseWriter: w}
	if d.status != http.StatusOK {
		http.Error(cw, d.reason, d.status)
		a.cfg.Audit.Record(audit.Event{Event: "request_denied", Outcome: "deny", Mode: a.cfg.Mode,
			ClientIP: remoteIP(r), Gateway: a.cfg.ID, Reason: d.reason, Detail: r.URL.Path})
	} else {
		r.Header.Set("X-SDP-Session", d.session.SessionID)
		r.Header.Set("X-SDP-Device", d.session.Device)
		if d.session.Username != "" {
			r.Header.Set("X-SDP-User", d.session.Username)
		}
		a.proxy.ServeHTTP(cw, r)
	}
	a.recordRequest(r, d, cw, a.cfg.Now().Sub(start))
}

func (a *Agent) recordRequest(r *http.Request, d decision, cw *countingWriter, dur time.Duration) {
	if ci, ok := connFromContext(r.Context()); ok {
		a.mu.Lock()
		ci.requests++
		a.mu.Unlock()
	}
	if d.session == nil {
		return
	}
	in := int64(len(r.Method) + len(r.URL.RequestURI()) + 12)
	for k, vs := range r.Header {
		for _, v := range vs {
			in += int64(len(k) + len(v) + 4)
		}
	}
	if r.ContentLength > 0 {
		in += r.ContentLength
	}
	status := cw.status
	if status == 0 {
		status = http.StatusOK
	}
	a.mu.Lock()
	d.session.stats.request(a.cfg.Now(), r.URL.Path, in, cw.n, status, dur)
	a.mu.Unlock()
}

type countingWriter struct {
	http.ResponseWriter
	n      int64
	status int
}

func (c *countingWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------------------------------------------------------------- connection tracking

type connInfo struct {
	ip       string
	opened   time.Time
	requests int
}

type connCtxKey struct{}

// ConnContext registers a new connection and stores its info in the request context
// (http.Server.ConnContext, called before the StateNew hook).
func (a *Agent) ConnContext(ctx context.Context, c net.Conn) context.Context {
	ci := &connInfo{ip: hostOf(c.RemoteAddr().String()), opened: a.cfg.Now()}
	a.mu.Lock()
	a.conns[c] = ci
	a.mu.Unlock()
	return context.WithValue(ctx, connCtxKey{}, ci)
}

func connFromContext(ctx context.Context) (*connInfo, bool) {
	ci, ok := ctx.Value(connCtxKey{}).(*connInfo)
	return ci, ok
}

// ConnState tracks open connections per address (http.Server.ConnState). Connections
// that stay open without completing a request are reported as "stalled" in telemetry.
func (a *Agent) ConnState(c net.Conn, state http.ConnState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch state {
	case http.StateNew:
		ip := hostOf(c.RemoteAddr().String())
		if _, ok := a.conns[c]; !ok {
			a.conns[c] = &connInfo{ip: ip, opened: a.cfg.Now()}
		}
		if s := a.newestLiveSessionLocked(ip); s != nil {
			s.stats.newConns++
		}
	case http.StateClosed, http.StateHijacked:
		delete(a.conns, c)
	}
}

func (a *Agent) newestLiveSessionLocked(ip string) *session {
	var best *session
	now := a.cfg.Now()
	for _, s := range a.sessions {
		if s.ClientIP == ip && !s.revoked && now.Before(s.ExpiresAt) && (best == nil || s.ExpiresAt.After(best.ExpiresAt)) {
			best = s
		}
	}
	return best
}

// ---------------------------------------------------------------- telemetry

// Snapshot closes the current window and returns one feature vector per live session
// that had activity or open connections.
func (a *Agent) Snapshot() api.TelemetryBatch {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.cfg.Now()
	secs := now.Sub(a.windowStart).Seconds()
	if secs <= 0 {
		secs = a.cfg.Window.Seconds()
	}
	open := map[string]int{}
	stalled := map[string]int{}
	for _, ci := range a.conns {
		open[ci.ip]++
		if ci.requests == 0 && now.Sub(ci.opened) >= a.cfg.StallThreshold {
			stalled[ci.ip]++
		}
	}
	batch := api.TelemetryBatch{FeatureSet: api.FeatureSet}
	ids := make([]string, 0, len(a.sessions))
	for id := range a.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := a.sessions[id]
		if s.revoked {
			s.stats = newWindowStats()
			continue
		}
		// Connection-level counts belong to the newest live session of the address.
		owner := a.newestLiveSessionLocked(s.ClientIP) == s
		o, st := 0, 0
		if owner {
			o, st = open[s.ClientIP], stalled[s.ClientIP]
		}
		if s.stats.requests == 0 && s.stats.newConns == 0 && o == 0 {
			continue
		}
		batch.Windows = append(batch.Windows, api.TelemetryWindow{
			SessionID: s.SessionID, Subject: s.Subject, Username: s.Username, Roles: s.Roles,
			ClientIP: s.ClientIP, Gateway: a.cfg.ID, WindowStart: a.windowStart, WindowSecs: secs,
			Features: s.stats.features(secs, o, st),
		})
		s.stats = newWindowStats()
	}
	a.windowStart = now
	return batch
}

// RunTelemetry exports a snapshot every window until ctx ends.
func (a *Agent) RunTelemetry(ctx context.Context) {
	if a.cfg.Telemetry == nil {
		return
	}
	t := time.NewTicker(a.cfg.Window)
	defer t.Stop()
	var lastErr time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b := a.Snapshot()
			if len(b.Windows) == 0 {
				continue
			}
			go func(b api.TelemetryBatch) {
				sctx, cancel := context.WithTimeout(ctx, a.cfg.Window)
				defer cancel()
				if err := a.cfg.Telemetry(sctx, b); err != nil && time.Since(lastErr) > 10*time.Second {
					lastErr = time.Now()
					a.cfg.Logger.Printf("telemetry export failed: %v", err)
				}
			}(b)
		}
	}
}

// ---------------------------------------------------------------- helpers

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func remoteIP(r *http.Request) string { return hostOf(r.RemoteAddr) }

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
