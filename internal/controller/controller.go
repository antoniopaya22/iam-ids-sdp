// Package controller implements the SDP Controller (policy decision point).
//
// Traditional mode: an Initiating Host is authenticated by its mTLS key pair only and
// authorized from the member registry. Proposed mode (paper, Sect. 5.6) adds a Keycloak
// access token obtained with MFA: the controller validates it (JWKS signature, issuer,
// audience, expiry, client, optional online introspection), binds it to the device,
// applies RBAC, and later revokes sessions (gateways + Keycloak) when the IDS raises an
// alert. Every decision is written to the audit log.
package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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

// TokenValidator validates IH access tokens (iam.Validator in production).
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*iam.Claims, error)
}

// IAMSessions checks and ends IdP sessions (iam.Admin in production).
type IAMSessions interface {
	Introspect(ctx context.Context, token string) (*iam.Introspection, error)
	LogoutUser(ctx context.Context, userID string) error
}

// GatewayClient pushes decisions to Accepting Hosts.
type GatewayClient interface {
	Install(ctx context.Context, gw Gateway, s api.GatewaySession) error
	Revoke(ctx context.Context, gw Gateway, r api.RevokeRequest) error
}

// Config of the controller.
type Config struct {
	Mode        string
	Policy      *policy.Policy
	SessionTTL  time.Duration
	GatewayTTL  time.Duration // gateways not heard from for this long are dropped
	RevokeScope string        // "session" or "subject" (every session of the identity)
	Validator   TokenValidator
	IAM         IAMSessions // optional: introspection + Keycloak logout
	Introspect  bool
	Gateways    GatewayClient
	Audit       *audit.Log
	PeerFunc    func(*http.Request) (tlsutil.Peer, error) // default: verified mTLS certificate
	Now         func() time.Time
}

// Gateway is a registered Accepting Host.
type Gateway struct {
	api.GatewayRegistration
	LastSeen time.Time `json:"last_seen"`
}

// Session is a granted IH session.
type Session struct {
	api.GatewaySession
	Service   string    `json:"service"`
	Gateways  []string  `json:"gateways"`
	State     string    `json:"state"` // active, revoked, terminated, expired
	CreatedAt time.Time `json:"created_at"`
	EndReason string    `json:"end_reason,omitempty"`
}

// Server is the controller.
type Server struct {
	cfg Config

	instance string // random id of this controller process (see api.RegistrationResponse)

	mu       sync.Mutex
	sessions map[string]*Session
	gateways map[string]*Gateway
}

// New returns a controller.
func New(cfg Config) (*Server, error) {
	if cfg.Mode != api.ModeTraditional && cfg.Mode != api.ModeProposed {
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if cfg.Mode == api.ModeProposed && cfg.Validator == nil {
		return nil, errors.New("proposed mode needs a token validator")
	}
	if cfg.Policy == nil || cfg.Gateways == nil || cfg.Audit == nil {
		return nil, errors.New("policy, gateway client and audit log are required")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 5 * time.Minute
	}
	if cfg.GatewayTTL == 0 {
		cfg.GatewayTTL = 45 * time.Second
	}
	if cfg.RevokeScope == "" {
		cfg.RevokeScope = "subject"
	}
	if cfg.PeerFunc == nil {
		cfg.PeerFunc = func(r *http.Request) (tlsutil.Peer, error) { return tlsutil.PeerOf(r.TLS) }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, instance: newID(), sessions: map[string]*Session{}, gateways: map[string]*Gateway{}}, nil
}

// Handler returns the mTLS API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", s.requireRole(api.OUDevice, s.handleCreateSession))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.requireRole(api.OUDevice, s.handleEndSession))
	mux.HandleFunc("POST /v1/gateways", s.requireRole(api.OUGateway, s.handleRegister))
	mux.HandleFunc("DELETE /v1/gateways/{id}", s.requireRole(api.OUGateway, s.handleDeregister))
	mux.HandleFunc("POST /v1/alerts", s.requireRole(api.OUIDS, s.handleAlert))
	return mux
}

func (s *Server) requireRole(role string, h func(http.ResponseWriter, *http.Request, tlsutil.Peer)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.cfg.PeerFunc(r)
		if err != nil || p.Role != role {
			s.cfg.Audit.Record(audit.Event{Event: "api_access", Outcome: "deny", Mode: s.cfg.Mode,
				ClientIP: remoteIP(r), Reason: fmt.Sprintf("%s %s requires a %s certificate (peer %q/%q)", r.Method, r.URL.Path, role, p.ID, p.Role)})
			writeErr(w, http.StatusForbidden, "client certificate not allowed for this endpoint")
			return
		}
		h(w, r, p)
	}
}

// ---------------------------------------------------------------- sessions

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request, peer tlsutil.Peer) {
	ctx := r.Context()
	start := time.Now()
	clientIP := remoteIP(r)
	var req api.SessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Service == "" {
		writeErr(w, http.StatusBadRequest, "body must be {\"service\": ...}")
		return
	}
	ev := audit.Event{Event: "session_request", Mode: s.cfg.Mode, Device: peer.ID, ClientIP: clientIP, Service: req.Service}
	deny := func(status int, reason string) {
		ev.Outcome, ev.Reason = "deny", reason
		s.cfg.Audit.Record(ev)
		writeErr(w, status, reason)
	}

	var claims *iam.Claims
	expires := s.cfg.Now().Add(s.cfg.SessionTTL)
	switch s.cfg.Mode {
	case api.ModeTraditional:
		if err := s.cfg.Policy.AuthorizeTraditional(peer.ID, req.Service); err != nil {
			deny(statusFor(err), err.Error())
			return
		}
	case api.ModeProposed:
		raw := bearer(r)
		var err error
		claims, err = s.cfg.Validator.Validate(ctx, raw)
		if err != nil {
			deny(http.StatusUnauthorized, "token rejected: "+err.Error())
			return
		}
		ev.Username, ev.Subject = claims.PreferredUsername, claims.Subject
		if s.cfg.Introspect && s.cfg.IAM != nil {
			in, err := s.cfg.IAM.Introspect(ctx, raw)
			if err != nil {
				deny(http.StatusServiceUnavailable, "token introspection failed: "+err.Error())
				return
			}
			if !in.Active {
				deny(http.StatusUnauthorized, iam.ErrInactive.Error())
				return
			}
		}
		if err := s.cfg.Policy.AuthorizeProposed(peer.ID, claims.PreferredUsername, claims.Roles(), req.Service); err != nil {
			deny(statusFor(err), err.Error())
			return
		}
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(expires) {
			expires = claims.ExpiresAt.Time
		}
	}
	svc, _ := s.cfg.Policy.Service(req.Service)

	gws := s.pickGateways(req.Gateways)
	if len(gws) == 0 {
		deny(http.StatusServiceUnavailable, "no accepting host available")
		return
	}

	sess := &Session{
		GatewaySession: api.GatewaySession{
			SessionID: newID(), Mode: s.cfg.Mode, Device: peer.ID, ClientIP: clientIP,
			Services: []string{req.Service}, ExpiresAt: expires,
		},
		Service: req.Service, State: "active", CreatedAt: s.cfg.Now(),
	}
	if claims != nil {
		sess.Subject, sess.Username, sess.TokenSID = claims.Subject, claims.PreferredUsername, claims.SessionID
		sess.Roles = claims.Roles()
	}
	ev.SessionID = sess.SessionID

	// Push the session to every selected AH (step 4 of the flow), each with its own SPA keys.
	type result struct {
		grant api.GatewayGrant
		err   error
	}
	results := make([]result, len(gws))
	var wg sync.WaitGroup
	for i, gw := range gws {
		wg.Add(1)
		go func(i int, gw Gateway) {
			defer wg.Done()
			key, hmacKey := spa.NewKeys()
			gs := sess.GatewaySession
			gs.KeyBase64, gs.HMACKeyBase64, gs.ServicePort = key, hmacKey, gw.ProxyPort
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			err := s.cfg.Gateways.Install(pctx, gw, gs)
			results[i] = result{err: err, grant: api.GatewayGrant{
				GatewayID: gw.ID, Address: gw.PublicAddr, SPAPort: gw.SPAPort, ServicePort: gw.ProxyPort,
				KeyBase64: key, HMACKeyBase64: hmacKey}}
		}(i, gw)
	}
	wg.Wait()
	var grants []api.GatewayGrant
	var failed []string
	for _, res := range results {
		if res.err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", res.grant.GatewayID, res.err))
			continue
		}
		grants = append(grants, res.grant)
		sess.Gateways = append(sess.Gateways, res.grant.GatewayID)
	}
	if len(grants) == 0 {
		deny(http.StatusBadGateway, "no accepting host accepted the session: "+strings.Join(failed, "; "))
		return
	}

	s.mu.Lock()
	s.sessions[sess.SessionID] = sess
	s.mu.Unlock()

	ev.Outcome = "allow"
	ev.Detail = map[string]any{"gateways": sess.Gateways, "failed_gateways": failed, "roles": sess.Roles,
		"expires_at": expires, "decision_ms": time.Since(start).Milliseconds()}
	s.cfg.Audit.Record(ev)

	writeJSON(w, http.StatusOK, api.SessionResponse{
		SessionID: sess.SessionID, Mode: s.cfg.Mode, Device: peer.ID, Subject: sess.Subject,
		Username: sess.Username, Service: req.Service, Path: svc.Path, ClientIP: clientIP,
		ExpiresAt: expires, Grants: grants,
	})
}

func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request, peer tlsutil.Peer) {
	id := r.PathValue("id")
	s.mu.Lock()
	sess, ok := s.sessions[id]
	owner := ok && sess.Device == peer.ID
	s.mu.Unlock()
	if !owner {
		writeErr(w, http.StatusNotFound, "no such session")
		return
	}
	s.endSessions(r.Context(), []string{id}, "terminated", "closed by the initiating host", false)
	w.WriteHeader(http.StatusNoContent)
}

// endSessions removes sessions from their gateways and, if logoutIAM is set, ends the
// users' Keycloak sessions so a new MFA login is required.
func (s *Server) endSessions(ctx context.Context, ids []string, state, reason string, logoutIAM bool) []string {
	type job struct {
		sess *Session
		gws  []Gateway
	}
	var jobs []job
	subjects := map[string]bool{}
	s.mu.Lock()
	for _, id := range ids {
		sess, ok := s.sessions[id]
		if !ok || sess.State != "active" {
			continue
		}
		sess.State, sess.EndReason = state, reason
		var gws []Gateway
		for _, g := range sess.Gateways {
			if gw, ok := s.gateways[g]; ok {
				gws = append(gws, *gw)
			}
		}
		jobs = append(jobs, job{sess: sess, gws: gws})
		if sess.Subject != "" {
			subjects[sess.Subject] = true
		}
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	var ended []string
	for _, j := range jobs {
		ended = append(ended, j.sess.SessionID)
		for _, gw := range j.gws {
			wg.Add(1)
			go func(sess *Session, gw Gateway) {
				defer wg.Done()
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer cancel()
				err := s.cfg.Gateways.Revoke(rctx, gw, api.RevokeRequest{
					SessionID: sess.SessionID, ClientIP: sess.ClientIP, TokenSID: sess.TokenSID, Reason: reason})
				outcome := "revoke"
				if err != nil {
					outcome = "error"
				}
				s.cfg.Audit.Record(audit.Event{Event: "gateway_revoke", Outcome: outcome, Mode: s.cfg.Mode,
					SessionID: sess.SessionID, Device: sess.Device, Username: sess.Username, ClientIP: sess.ClientIP,
					Gateway: gw.ID, Reason: reason, Detail: errString(err)})
			}(j.sess, gw)
		}
		s.cfg.Audit.Record(audit.Event{Event: "session_" + state, Outcome: "revoke", Mode: s.cfg.Mode,
			SessionID: j.sess.SessionID, Device: j.sess.Device, Username: j.sess.Username, Subject: j.sess.Subject,
			ClientIP: j.sess.ClientIP, Service: j.sess.Service, Reason: reason})
	}
	if logoutIAM && s.cfg.IAM != nil {
		for sub := range subjects {
			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer cancel()
				err := s.cfg.IAM.LogoutUser(lctx, sub)
				outcome := "revoke"
				if err != nil {
					outcome = "error"
				}
				s.cfg.Audit.Record(audit.Event{Event: "iam_logout", Outcome: outcome, Mode: s.cfg.Mode,
					Subject: sub, Reason: reason, Detail: errString(err)})
			}(sub)
		}
	}
	wg.Wait()
	sort.Strings(ended)
	return ended
}

// ---------------------------------------------------------------- alerts

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request, peer tlsutil.Peer) {
	var a api.Alert
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&a); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid alert")
		return
	}
	ev := audit.Event{Event: "ids_alert", Mode: s.cfg.Mode, SessionID: a.SessionID, Username: a.Username,
		Subject: a.Subject, ClientIP: a.ClientIP, Gateway: a.Gateway,
		Reason: fmt.Sprintf("[%s] %s", a.Detector, a.Reason),
		Detail: map[string]any{"score": a.Score, "severity": a.Severity, "ids": peer.ID}}

	ids := s.sessionsToRevoke(a)
	if len(ids) == 0 {
		ev.Outcome = "info"
		s.cfg.Audit.Record(ev)
		writeJSON(w, http.StatusOK, api.AlertResponse{Action: "ignored", Detail: "no active session matches the alert"})
		return
	}
	ev.Outcome = "revoke"
	s.cfg.Audit.Record(ev)
	reason := fmt.Sprintf("IDS alert from %s: [%s] %s", peer.ID, a.Detector, a.Reason)
	revoked := s.endSessions(r.Context(), ids, "revoked", reason, s.cfg.Mode == api.ModeProposed)
	writeJSON(w, http.StatusOK, api.AlertResponse{Action: "revoked", Revoked: revoked})
}

// sessionsToRevoke returns the active session named by the alert and, with scope
// "subject", every other active session of the same identity (or device, without IAM).
func (s *Server) sessionsToRevoke(a api.Alert) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.sessions[a.SessionID]
	if !ok || target.State != "active" {
		return nil
	}
	ids := []string{target.SessionID}
	if s.cfg.RevokeScope == "subject" {
		for id, sess := range s.sessions {
			if id == target.SessionID || sess.State != "active" {
				continue
			}
			sameIdentity := target.Subject != "" && sess.Subject == target.Subject
			sameDevice := target.Subject == "" && sess.Device == target.Device
			if sameIdentity || sameDevice {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// AdminRevoke ends the active sessions of a device and/or a user (administrator
// intervention). With logoutIAM the users' Keycloak sessions are ended too.
func (s *Server) AdminRevoke(ctx context.Context, device, username, reason string, logoutIAM bool) []string {
	if device == "" && username == "" {
		return nil
	}
	var ids []string
	s.mu.Lock()
	for id, sess := range s.sessions {
		if sess.State != "active" {
			continue
		}
		if (device == "" || sess.Device == device) && (username == "" || sess.Username == username) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	if reason == "" {
		reason = "revoked by an administrator"
	}
	s.cfg.Audit.Record(audit.Event{Event: "admin_revoke", Outcome: "revoke", Mode: s.cfg.Mode, Device: device,
		Username: username, Reason: reason, Detail: map[string]any{"sessions": len(ids)}})
	return s.endSessions(ctx, ids, "revoked", reason, logoutIAM && s.cfg.Mode == api.ModeProposed)
}

// ---------------------------------------------------------------- gateways

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request, peer tlsutil.Peer) {
	var reg api.GatewayRegistration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&reg); err != nil ||
		reg.ID == "" || net.ParseIP(reg.PublicAddr) == nil || !strings.HasPrefix(reg.ControlURL, "https://") ||
		reg.ProxyPort == 0 || reg.SPAPort == 0 {
		writeErr(w, http.StatusBadRequest, "invalid registration")
		return
	}
	s.mu.Lock()
	_, known := s.gateways[reg.ID]
	s.gateways[reg.ID] = &Gateway{GatewayRegistration: reg, LastSeen: s.cfg.Now()}
	s.mu.Unlock()
	if !known {
		s.cfg.Audit.Record(audit.Event{Event: "gateway_registered", Outcome: "info", Mode: s.cfg.Mode,
			Gateway: reg.ID, ClientIP: remoteIP(r), Detail: reg})
	}
	writeJSON(w, http.StatusOK, api.RegistrationResponse{Instance: s.instance})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request, peer tlsutil.Peer) {
	id := r.PathValue("id")
	s.mu.Lock()
	delete(s.gateways, id)
	s.mu.Unlock()
	s.cfg.Audit.Record(audit.Event{Event: "gateway_deregistered", Outcome: "info", Mode: s.cfg.Mode, Gateway: id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pickGateways(want []string) []Gateway {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Gateway
	for id, gw := range s.gateways {
		if len(want) == 0 || contains(want, id) {
			out = append(out, *gw)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------------------------------------------------------------- housekeeping

// Housekeep expires sessions and forgets silent gateways; run it periodically.
func (s *Server) Housekeep(ctx context.Context) {
	now := s.cfg.Now()
	var expired []string
	s.mu.Lock()
	for id, sess := range s.sessions {
		if sess.State == "active" && now.After(sess.ExpiresAt) {
			expired = append(expired, id)
		}
		if sess.State != "active" && now.Sub(sess.ExpiresAt) > time.Hour {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
	if len(expired) > 0 {
		s.endSessions(ctx, expired, "expired", "session lifetime reached", false)
	}
	s.mu.Lock()
	for id, gw := range s.gateways {
		if now.Sub(gw.LastSeen) > s.cfg.GatewayTTL {
			delete(s.gateways, id)
		}
	}
	s.mu.Unlock()
}

// Status is a summary for health checks and scripts.
type Status struct {
	Mode           string     `json:"mode"`
	Gateways       []Gateway  `json:"gateways"`
	ActiveSessions int        `json:"active_sessions"`
	Sessions       []*Session `json:"sessions,omitempty"`
}

// Status returns the current state (sessions are included when verbose is set).
func (s *Server) Status(verbose bool) Status {
	st := Status{Mode: s.cfg.Mode, Gateways: s.pickGateways(nil)}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.State == "active" {
			st.ActiveSessions++
		}
		if verbose {
			c := *sess
			c.KeyBase64, c.HMACKeyBase64 = "", ""
			st.Sessions = append(st.Sessions, &c)
		}
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].CreatedAt.Before(st.Sessions[j].CreatedAt) })
	return st
}

// ---------------------------------------------------------------- helpers

func statusFor(err error) int {
	switch {
	case errors.Is(err, policy.ErrUnknownService):
		return http.StatusNotFound
	case errors.Is(err, policy.ErrUnknownDevice), errors.Is(err, policy.ErrForbidden):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func errString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
