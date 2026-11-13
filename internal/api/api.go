// Package api holds the JSON messages exchanged by the SDP components.
//
//	IH (sdp-client)  -> controller : SessionRequest / SessionResponse (mTLS, + Bearer token in proposed mode)
//	controller -> AH (sdp-gateway) : GatewaySession (mTLS, management network)
//	AH -> controller               : GatewayRegistration (mTLS, management network)
//	AH -> IDS                      : TelemetryBatch (mTLS, management network)
//	IDS -> controller              : Alert (mTLS, management network)
package api

import "time"

// Operating modes of the lab.
const (
	ModeTraditional = "traditional" // key pairs + mTLS + SPA only
	ModeProposed    = "proposed"    // + Keycloak (MFA, RBAC, tokens) + IDS/UEBA
)

// Certificate organisational units used to tell component roles apart.
const (
	OUDevice     = "device"
	OUGateway    = "gateway"
	OUController = "controller"
	OUIDS        = "ids"
)

// SessionRequest is sent by an Initiating Host to the controller.
type SessionRequest struct {
	Service  string   `json:"service"`
	Gateways []string `json:"gateways,omitempty"` // empty: every registered gateway
}

// GatewayGrant tells the IH how to reach one Accepting Host for a session.
type GatewayGrant struct {
	GatewayID     string `json:"gateway_id"`
	Address       string `json:"address"`  // public IP of the gateway
	SPAPort       int    `json:"spa_port"` // UDP port fwknopd sniffs
	ServicePort   int    `json:"service_port"`
	KeyBase64     string `json:"key_base64"`
	HMACKeyBase64 string `json:"hmac_key_base64"`
}

// SessionResponse is the controller's answer to an authorized SessionRequest.
type SessionResponse struct {
	SessionID string         `json:"session_id"`
	Mode      string         `json:"mode"`
	Device    string         `json:"device"`
	Subject   string         `json:"subject,omitempty"`
	Username  string         `json:"username,omitempty"`
	Service   string         `json:"service"`
	Path      string         `json:"path"`
	ClientIP  string         `json:"client_ip"`
	ExpiresAt time.Time      `json:"expires_at"`
	Grants    []GatewayGrant `json:"grants"`
}

// GatewaySession is pushed by the controller to an AH to install a session.
type GatewaySession struct {
	SessionID     string    `json:"session_id"`
	Mode          string    `json:"mode"`
	Device        string    `json:"device"`
	Subject       string    `json:"subject,omitempty"`  // Keycloak user id (sub), proposed mode
	Username      string    `json:"username,omitempty"` // preferred_username, proposed mode
	TokenSID      string    `json:"token_sid,omitempty"`
	Roles         []string  `json:"roles,omitempty"`
	Services      []string  `json:"services"`
	ClientIP      string    `json:"client_ip"`
	ServicePort   int       `json:"service_port"`
	KeyBase64     string    `json:"key_base64"`
	HMACKeyBase64 string    `json:"hmac_key_base64"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// RevokeRequest is sent by the controller to an AH to tear a session down.
type RevokeRequest struct {
	SessionID string `json:"session_id"`
	ClientIP  string `json:"client_ip"`
	TokenSID  string `json:"token_sid,omitempty"`
	Reason    string `json:"reason"`
}

// GatewayRegistration announces an AH to the controller.
type GatewayRegistration struct {
	ID         string `json:"id"`
	PublicAddr string `json:"public_addr"` // where IHs send SPA and connect
	ControlURL string `json:"control_url"` // where the controller pushes sessions
	SPAPort    int    `json:"spa_port"`
	ProxyPort  int    `json:"proxy_port"`
}

// Alert is raised by the IDS when a session behaves suspiciously.
type Alert struct {
	SessionID string    `json:"session_id"`
	Subject   string    `json:"subject,omitempty"`
	Username  string    `json:"username,omitempty"`
	ClientIP  string    `json:"client_ip"`
	Gateway   string    `json:"gateway"`
	Detector  string    `json:"detector"` // "apollon-mab", "ueba-rate", "ueba-multi-ip", ...
	Reason    string    `json:"reason"`
	Score     float64   `json:"score"`
	Severity  string    `json:"severity"`
	Time      time.Time `json:"time"`
}

// AlertResponse lists what the controller did with an alert.
type AlertResponse struct {
	Action  string   `json:"action"` // "revoked", "ignored"
	Revoked []string `json:"revoked,omitempty"`
	Detail  string   `json:"detail,omitempty"`
}

// TelemetryWindow summarises the activity of one session on one AH during a time window.
// Feature names must stay in sync with ids/sdp_ids/features.py (feature set "sdp-window-v1").
type TelemetryWindow struct {
	SessionID   string    `json:"session_id"`
	Subject     string    `json:"subject,omitempty"`
	Username    string    `json:"username,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	ClientIP    string    `json:"client_ip"`
	Gateway     string    `json:"gateway"`
	WindowStart time.Time `json:"window_start"`
	WindowSecs  float64   `json:"window_secs"`

	Features map[string]float64 `json:"features"`
}

// TelemetryBatch is what an AH posts to the IDS every window.
type TelemetryBatch struct {
	FeatureSet string            `json:"feature_set"`
	Windows    []TelemetryWindow `json:"windows"`
}

// FeatureSet is the identifier of the telemetry schema exported by the AH.
const FeatureSet = "sdp-window-v1"

// ErrorResponse is the JSON body of every non-2xx answer.
type ErrorResponse struct {
	Error string `json:"error"`
}
