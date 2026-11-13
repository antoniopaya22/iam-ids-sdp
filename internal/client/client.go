// Package client implements the SDP Initiating Host (IH).
//
// Proposed flow (paper, Sect. 5.6), each step timed and its bytes on the wire counted:
//
//  1. log in to Keycloak with password + TOTP and get an access token (proposed mode);
//  2. send an SPA packet (device keys) so the controller's port opens for this host;
//  3. open mTLS to the controller (device key pair) and request a session for a service,
//     presenting the token;
//  4. send an SPA packet (per-session keys) to every Accepting Host granted;
//  5. open mTLS to each AH and request the service (with the token in proposed mode).
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

// Config of the IH.
type Config struct {
	Mode           string
	DeviceDir      string // ca.crt, tls.crt, tls.key, spa.keys
	ControllerHost string
	ControllerPort int
	ControllerSPA  bool // knock on the controller before connecting (default true in the lab)
	Issuer         string
	ClientID       string
	GatewayName    string // DNS SAN expected in gateway certificates
	ControllerName string // DNS SAN expected in the controller certificate
}

// Credentials of the user (proposed mode).
type Credentials struct {
	Username   string
	Password   string
	TOTPSecret string // raw secret; empty means "do not send a TOTP code"
	Token      string // use this token instead of logging in
}

// Timings of one connection set-up, in milliseconds.
type Timings struct {
	Token         float64 `json:"token_ms"`
	ControllerSPA float64 `json:"controller_spa_ms"`
	Controller    float64 `json:"controller_ms"`
	GatewaySPA    float64 `json:"gateway_spa_ms"`
	FirstRequest  float64 `json:"first_request_ms"`
	Total         float64 `json:"total_ms"`
}

// Bytes exchanged during one connection set-up (sent + received, TCP/UDP payload).
type Bytes struct {
	Token         int64 `json:"token"`
	ControllerSPA int64 `json:"controller_spa"`
	Controller    int64 `json:"controller"`
	GatewaySPA    int64 `json:"gateway_spa"`
	FirstRequest  int64 `json:"first_request"`
	Total         int64 `json:"total"`
}

// Result of Connect.
type Result struct {
	Session  api.SessionResponse `json:"session"`
	Token    string              `json:"token,omitempty"`
	Status   map[string]int      `json:"status"` // first request status per gateway
	Timings  Timings             `json:"timings"`
	Bytes    Bytes               `json:"bytes"`
	Username string              `json:"username,omitempty"`
}

// Client is an Initiating Host.
type Client struct {
	cfg      Config
	tlsCtrl  *tls.Config
	tlsGW    *tls.Config
	caClient func(counter *Counter) *http.Client
	spaKeys  spa.KeyFile
}

// New loads the device credentials.
func New(cfg Config) (*Client, error) {
	if cfg.ControllerPort == 0 {
		cfg.ControllerPort = 8443
	}
	if cfg.GatewayName == "" {
		cfg.GatewayName = "sdp-gateway"
	}
	if cfg.ControllerName == "" {
		cfg.ControllerName = cfg.ControllerHost
	}
	files := tlsutil.Files{Dir: cfg.DeviceDir}
	tc, err := tlsutil.ClientConfig(files, cfg.ControllerName)
	if err != nil {
		return nil, fmt.Errorf("device credentials: %w", err)
	}
	tg, err := tlsutil.ClientConfig(files, cfg.GatewayName)
	if err != nil {
		return nil, err
	}
	pool, err := tlsutil.Pool(files.CA())
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, tlsCtrl: tc, tlsGW: tg}
	c.caClient = func(counter *Counter) *http.Client {
		return counter.HTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, 15*time.Second)
	}
	if cfg.ControllerSPA {
		b, err := os.ReadFile(filepath.Join(cfg.DeviceDir, "spa.keys"))
		if err != nil {
			return nil, err
		}
		if c.spaKeys, err = spa.ParseKeyFile(b); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Login obtains an access token from Keycloak (password + TOTP).
func (c *Client) Login(ctx context.Context, cr Credentials) (string, int64, error) {
	counter := &Counter{}
	code := ""
	if cr.TOTPSecret != "" {
		code = iam.TOTP([]byte(cr.TOTPSecret), time.Now(), 30, 6)
	}
	tr, err := iam.PasswordLogin(ctx, c.caClient(counter), c.cfg.Issuer+"/protocol/openid-connect/token",
		c.cfg.ClientID, cr.Username, cr.Password, code)
	if err != nil {
		return "", counter.Total(), err
	}
	return tr.AccessToken, counter.Total(), nil
}

// Connect runs the whole flow for one service and performs the first request on every
// granted AH.
func (c *Client) Connect(ctx context.Context, service string, cr Credentials) (*Result, error) {
	res := &Result{Status: map[string]int{}, Username: cr.Username}
	t0 := time.Now()
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

	// 1. IAM login (proposed mode).
	token := cr.Token
	if c.cfg.Mode == api.ModeProposed && token == "" && cr.Username != "" {
		start := time.Now()
		var n int64
		var err error
		token, n, err = c.Login(ctx, cr)
		res.Timings.Token, res.Bytes.Token = ms(time.Since(start)), n
		if err != nil {
			return res, fmt.Errorf("IAM login: %w", err)
		}
	}
	res.Token = token

	// 2. SPA to the controller.
	ctrlIP, err := resolve(ctx, c.cfg.ControllerHost)
	if err != nil {
		return res, err
	}
	ctrlAddr := net.JoinHostPort(ctrlIP, fmt.Sprint(c.cfg.ControllerPort))
	if c.cfg.ControllerSPA {
		start := time.Now()
		n, err := c.knockAndWait(ctx, ctrlIP, 62201, c.cfg.ControllerPort, c.spaKeys.KeyBase64, c.spaKeys.HMACKeyBase64)
		res.Timings.ControllerSPA, res.Bytes.ControllerSPA = ms(time.Since(start)), n
		if err != nil {
			return res, fmt.Errorf("controller SPA: %w", err)
		}
	}

	// 3. mTLS session request.
	start := time.Now()
	counter := &Counter{}
	sess, err := c.requestSession(ctx, counter, ctrlAddr, service, token)
	res.Timings.Controller, res.Bytes.Controller = ms(time.Since(start)), counter.Total()
	if err != nil {
		return res, err
	}
	res.Session = *sess

	// 4 + 5. SPA to every AH, then the first request, in parallel.
	var mu sync.Mutex
	var wg sync.WaitGroup
	var spaMax, reqMax time.Duration
	var errs []string
	for _, g := range sess.Grants {
		wg.Add(1)
		go func(g api.GatewayGrant) {
			defer wg.Done()
			s0 := time.Now()
			n, err := c.knockAndWait(ctx, g.Address, g.SPAPort, g.ServicePort, g.KeyBase64, g.HMACKeyBase64)
			spaDur := time.Since(s0)
			r0 := time.Now()
			rc := &Counter{}
			status := 0
			if err == nil {
				status, err = c.get(ctx, rc, g, sess.Path, token)
			}
			reqDur := time.Since(r0)
			mu.Lock()
			defer mu.Unlock()
			res.Bytes.GatewaySPA += n
			res.Bytes.FirstRequest += rc.Total()
			res.Status[g.GatewayID] = status
			spaMax, reqMax = max(spaMax, spaDur), max(reqMax, reqDur)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", g.GatewayID, err))
			}
		}(g)
	}
	wg.Wait()
	res.Timings.GatewaySPA, res.Timings.FirstRequest = ms(spaMax), ms(reqMax)
	res.Timings.Total = ms(time.Since(t0))
	res.Bytes.Total = res.Bytes.Token + res.Bytes.ControllerSPA + res.Bytes.Controller + res.Bytes.GatewaySPA + res.Bytes.FirstRequest
	if len(errs) > 0 {
		return res, errors.New(strings.Join(errs, "; "))
	}
	return res, nil
}

// ErrDenied is returned when the controller refuses a session.
type ErrDenied struct {
	Status int
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("controller denied the session (%d): %s", e.Status, e.Reason)
}

func (c *Client) requestSession(ctx context.Context, counter *Counter, addr, service, token string) (*api.SessionResponse, error) {
	body, _ := json.Marshal(api.SessionRequest{Service: service})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/v1/sessions", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := counter.HTTPClient(c.tlsCtrl, 20*time.Second).Do(req)
	if err != nil {
		return nil, fmt.Errorf("controller: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e api.ErrorResponse
		_ = json.Unmarshal(b, &e)
		return nil, &ErrDenied{Status: resp.StatusCode, Reason: e.Error}
	}
	var sr api.SessionResponse
	if err := json.Unmarshal(b, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}

// knockAndWait sends an SPA packet and waits until the TCP port accepts connections,
// re-sending the packet once if it seems lost.
func (c *Client) knockAndWait(ctx context.Context, host string, spaPort, tcpPort int, key, hmacKey string) (int64, error) {
	allow, err := localIPTowards(host)
	if err != nil {
		return 0, err
	}
	k := spa.Knock{Server: host, Port: spaPort, Access: fmt.Sprintf("tcp/%d", tcpPort), AllowIP: allow,
		KeyBase64: key, HMACKeyBase64: hmacKey}
	var total int64
	for attempt := 0; attempt < 3; attempt++ {
		n, err := k.Send(ctx)
		total += int64(n)
		if err != nil {
			return total, err
		}
		// The port is filtered (DROP) until fwknopd adds the rule, so each probe is a SYN
		// that gets no answer: keep the probe timeout short to measure the opening time
		// with a few milliseconds of resolution.
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			conn, err := (&net.Dialer{Timeout: 20 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(tcpPort)))
			if err == nil {
				_ = conn.Close()
				return total, nil
			}
			if ctx.Err() != nil {
				return total, ctx.Err()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	return total, fmt.Errorf("port %s:%d still closed after SPA", host, tcpPort)
}

// get performs one request to an AH and returns the HTTP status.
func (c *Client) get(ctx context.Context, counter *Counter, g api.GatewayGrant, path, token string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s:%d%s", g.Address, g.ServicePort, path), nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := counter.HTTPClient(c.tlsGW, 10*time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// Disconnect ends a session at the controller (it opens the controller port first).
func (c *Client) Disconnect(ctx context.Context, sessionID string) error {
	ctrlIP, err := resolve(ctx, c.cfg.ControllerHost)
	if err != nil {
		return err
	}
	if c.cfg.ControllerSPA {
		if _, err := c.knockAndWait(ctx, ctrlIP, 62201, c.cfg.ControllerPort, c.spaKeys.KeyBase64, c.spaKeys.HMACKeyBase64); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("https://%s/v1/sessions/%s", net.JoinHostPort(ctrlIP, fmt.Sprint(c.cfg.ControllerPort)), sessionID), nil)
	if err != nil {
		return err
	}
	resp, err := tlsutil.HTTPClient(c.tlsCtrl, 10*time.Second).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("disconnect: %s", resp.Status)
	}
	return nil
}

// GatewayClient returns an HTTP client for the data channel (mTLS with the device key
// pair); keepAlive=false forces a new TCP+TLS connection per request.
func (c *Client) GatewayClient(counter *Counter, keepAlive bool, timeout time.Duration) *http.Client {
	hc := counter.HTTPClient(c.tlsGW, timeout)
	tr := hc.Transport.(*http.Transport)
	tr.DisableKeepAlives = !keepAlive
	tr.MaxIdleConnsPerHost = 64
	return hc
}

func resolve(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", host)
}

// localIPTowards returns the source address the kernel uses to reach host (no packet is sent).
func localIPTowards(host string) (string, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(host, "9"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// ---------------------------------------------------------------- byte counting

// Counter accumulates bytes read and written on connections it dialled.
type Counter struct {
	read, written atomic.Int64
}

// Total returns bytes sent + received.
func (c *Counter) Total() int64 { return c.read.Load() + c.written.Load() }

// HTTPClient returns a client (fresh transport, no connection reuse with other phases)
// whose connections are counted.
func (c *Counter) HTTPClient(cfg *tls.Config, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.Proxy = nil
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: conn, c: c}, nil
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

type countingConn struct {
	net.Conn
	c *Counter
}

func (cc *countingConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Read(b)
	cc.c.read.Add(int64(n))
	return n, err
}

func (cc *countingConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Write(b)
	cc.c.written.Add(int64(n))
	return n, err
}

// ---------------------------------------------------------------- session file

// SessionFile persists a connected session so later commands can use it.
type SessionFile struct {
	Session  api.SessionResponse `json:"session"`
	Token    string              `json:"token,omitempty"`
	Username string              `json:"username,omitempty"`
	Device   string              `json:"device"`
}

// Save writes the session file with mode 0600.
func (s SessionFile) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadSession reads a session file.
func LoadSession(path string) (*SessionFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s SessionFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if len(s.Session.Grants) == 0 {
		return nil, errors.New("session file has no gateway grants")
	}
	return &s, nil
}
