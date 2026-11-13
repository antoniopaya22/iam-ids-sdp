// Command sdp-gateway is the SDP Accepting Host (AH).
//
// It closes the public interface (default-drop iptables), runs fwknopd with one stanza
// per session the controller installs, and serves an mTLS reverse proxy in front of the
// protected service. In proposed mode the proxy validates every bearer token on its own
// (JWKS signature, issuer, audience, expiry, roles) and exports per-session request
// features to the IDS. Configuration comes from SDP_* environment variables.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/audit"
	"github.com/antoniopaya22/iam-ids-sdp/internal/cli"
	"github.com/antoniopaya22/iam-ids-sdp/internal/gateway"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/policy"
	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: sdp-gateway [serve]")
		os.Exit(2)
	}
	if err := serve(); err != nil {
		log.Fatalf("sdp-gateway: %v", err)
	}
}

func serve() error {
	ctx, stop := cli.SignalContext()
	defer stop()
	logger := log.New(os.Stderr, "[gateway] ", log.LstdFlags)

	mode := cli.Env("SDP_MODE", api.ModeTraditional)
	pol, err := policy.Load(cli.Env("SDP_POLICY", "/etc/sdp/policy.yaml"))
	if err != nil {
		return err
	}
	files := tlsutil.Files{Dir: cli.Env("SDP_TLS_DIR", "/etc/sdp/tls")}
	upstream, err := url.Parse(cli.Env("SDP_UPSTREAM", "http://web:80"))
	if err != nil {
		return err
	}
	pubIf, pubIP, err := spa.InterfaceFor(cli.Env("SDP_PUBLIC_SUBNET", "10.233.0.0/24"))
	if err != nil {
		return err
	}
	mgmtIf, mgmtIP, err := spa.InterfaceFor(cli.Env("SDP_INTERNAL_SUBNET", "10.233.2.0/24"))
	if err != nil {
		return err
	}
	id := cli.Env("SDP_GATEWAY_ID", "gw-"+pubIP[strings.LastIndex(pubIP, ".")+1:])
	al, err := audit.New(id, cli.Env("SDP_AUDIT_LOG", "/var/log/sdp/audit.jsonl"))
	if err != nil {
		return err
	}
	proxyPort := cli.EnvInt("SDP_PROXY_PORT", 8443)
	controlPort := cli.EnvInt("SDP_CONTROL_PORT", 9443)
	spaPort := cli.EnvInt("SDP_SPA_PORT", 62201)

	// Dark by default: only loopback, replies and the management network get in.
	fw := spa.Firewall{Run: spa.ExecRunner}
	if err := fw.DefaultDrop(ctx, []string{mgmtIf}); err != nil {
		return err
	}
	daemon := spa.NewDaemon(spa.DaemonConfig{Dir: "/run/fwknop", Interface: pubIf, SPAPort: spaPort,
		Logger: log.New(os.Stderr, "[fwknopd] ", log.LstdFlags)})
	if err := daemon.Start(ctx); err != nil {
		return err
	}
	defer daemon.Stop()

	cfg := gateway.Config{
		ID: id, Mode: mode, Policy: pol, Upstream: upstream, SPA: daemon, Firewall: fw,
		Window: cli.EnvDuration("SDP_TELEMETRY_WINDOW", 2*time.Second), Audit: al, Logger: logger,
	}
	if mode == api.ModeProposed {
		issuer := cli.Env("SDP_OIDC_ISSUER", "https://keycloak:8443/realms/sdp")
		kc, err := tlsutil.CAClient(files.CA(), 10*time.Second)
		if err != nil {
			return err
		}
		dctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		disc, err := iam.DiscoverWithRetry(dctx, kc, issuer, 2*time.Second)
		cancel()
		if err != nil {
			return err
		}
		jwks := iam.NewJWKS(disc.JWKSURI, kc)
		if err := jwks.Refresh(ctx); err != nil {
			return err
		}
		cfg.Validator = iam.NewCachingValidator(&iam.Validator{
			Issuer:          disc.Issuer,
			Audience:        cli.Env("SDP_OIDC_AUDIENCE", "sdp-gateway"),
			AuthorizedParty: cli.Env("SDP_OIDC_CLIENT", "sdp-client"),
			Leeway:          5 * time.Second,
			JWKS:            jwks,
		})
		if idsURL := cli.Env("SDP_IDS_URL", ""); idsURL != "" {
			idsTLS, err := tlsutil.ClientConfig(files, cli.Env("SDP_IDS_NAME", "ids"))
			if err != nil {
				return err
			}
			cfg.Telemetry = telemetrySink(tlsutil.HTTPClient(idsTLS, 5*time.Second), strings.TrimRight(idsURL, "/")+"/v1/telemetry")
		}
	}
	agent, err := gateway.New(cfg)
	if err != nil {
		return err
	}

	srvTLS, err := tlsutil.ServerConfig(files)
	if err != nil {
		return err
	}
	quiet := log.New(io.Discard, "", 0)
	proxy := &http.Server{
		Addr: net.JoinHostPort(pubIP, fmt.Sprint(proxyPort)), Handler: agent, TLSConfig: srvTLS,
		ConnContext: agent.ConnContext, ConnState: agent.ConnState,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, ErrorLog: quiet,
	}
	control := &http.Server{
		Addr: net.JoinHostPort(mgmtIP, fmt.Sprint(controlPort)), Handler: agent.ControlHandler(),
		TLSConfig: srvTLS.Clone(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: quiet,
	}
	errCh := make(chan error, 2)
	go func() { errCh <- proxy.ListenAndServeTLS("", "") }()
	go func() { errCh <- control.ListenAndServeTLS("", "") }()

	// Register with the controller (and keep doing it: it is also the heartbeat).
	ctrlTLS, err := tlsutil.ClientConfig(files, cli.Env("SDP_CONTROLLER_NAME", "controller-mgmt"))
	if err != nil {
		return err
	}
	ctrl := tlsutil.HTTPClient(ctrlTLS, 5*time.Second)
	ctrlURL := strings.TrimRight(cli.Env("SDP_CONTROLLER_URL", "https://controller-mgmt:8443"), "/")
	reg := api.GatewayRegistration{ID: id, PublicAddr: pubIP, ControlURL: fmt.Sprintf("https://%s:%d", mgmtIP, controlPort),
		SPAPort: spaPort, ProxyPort: proxyPort}
	registered := make(chan struct{})
	go func() {
		first := true
		for {
			if err := register(ctx, ctrl, ctrlURL, reg); err != nil {
				logger.Printf("registration: %v", err)
			} else if first {
				first = false
				logger.Printf("registered with %s as %s (public %s, management %s)", ctrlURL, id, pubIP, mgmtIP)
				close(registered)
			}
			wait := 10 * time.Second
			if first {
				wait = 2 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
	go agent.RunTelemetry(ctx)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				agent.Expire(ctx)
			}
		}
	}()
	go func() {
		select {
		case <-registered:
			_ = os.WriteFile("/tmp/sdp-ready", []byte("ok\n"), 0o644)
		case <-ctx.Done():
		}
	}()
	al.Record(audit.Event{Event: "gateway_started", Outcome: "info", Mode: mode, Gateway: id})
	logger.Printf("mode %s: proxy %s -> %s, control %s, SPA on %s udp/%d", mode, proxy.Addr, upstream, control.Addr, pubIf, spaPort)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if req, err := http.NewRequestWithContext(sctx, http.MethodDelete, ctrlURL+"/v1/gateways/"+url.PathEscape(id), nil); err == nil {
		if resp, err := ctrl.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	_ = proxy.Shutdown(sctx)
	_ = control.Shutdown(sctx)
	return nil
}

func register(ctx context.Context, c *http.Client, ctrlURL string, reg api.GatewayRegistration) error {
	return postJSON(ctx, c, ctrlURL+"/v1/gateways", reg)
}

func telemetrySink(c *http.Client, u string) gateway.TelemetrySink {
	return func(ctx context.Context, b api.TelemetryBatch) error { return postJSON(ctx, c, u, b) }
}

func postJSON(ctx context.Context, c *http.Client, u string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
