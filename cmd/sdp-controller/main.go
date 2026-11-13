// Command sdp-controller is the SDP Controller (policy decision point).
//
//	sdp-controller serve              run the controller (configured with SDP_* variables)
//	sdp-controller status [-sessions] print gateways and sessions (local status port)
//
// In the lab the controller is itself dark: its public interface drops everything until a
// registered device sends an SPA packet with its static device keys. The internal
// (management) interface is trusted: gateways register and the IDS posts alerts there.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/audit"
	"github.com/antoniopaya22/iam-ids-sdp/internal/cli"
	"github.com/antoniopaya22/iam-ids-sdp/internal/controller"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
	"github.com/antoniopaya22/iam-ids-sdp/internal/policy"
	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		if err := serve(); err != nil {
			log.Fatalf("sdp-controller: %v", err)
		}
	case "status":
		status(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: sdp-controller serve | status [-sessions] [-json]")
		os.Exit(2)
	}
}

func serve() error {
	ctx, stop := cli.SignalContext()
	defer stop()
	logger := log.New(os.Stderr, "[controller] ", log.LstdFlags)

	mode := cli.Env("SDP_MODE", api.ModeTraditional)
	pol, err := policy.Load(cli.Env("SDP_POLICY", "/etc/sdp/policy.yaml"))
	if err != nil {
		return err
	}
	files := tlsutil.Files{Dir: cli.Env("SDP_TLS_DIR", "/etc/sdp/tls")}
	al, err := audit.New("controller", cli.Env("SDP_AUDIT_LOG", "/var/log/sdp/audit.jsonl"))
	if err != nil {
		return err
	}

	// Dark controller: default-drop firewall + fwknopd with one stanza per device.
	if cli.EnvBool("SDP_SPA", true) {
		if err := startSPA(ctx, pol, logger); err != nil {
			return fmt.Errorf("spa: %w", err)
		}
	}

	gwTLS, err := tlsutil.ClientConfig(files, cli.Env("SDP_GATEWAY_NAME", "sdp-gateway"))
	if err != nil {
		return err
	}
	cfg := controller.Config{
		Mode:        mode,
		Policy:      pol,
		SessionTTL:  cli.EnvDuration("SDP_SESSION_TTL", 5*time.Minute),
		RevokeScope: cli.Env("SDP_REVOKE_SCOPE", "subject"),
		Gateways:    controller.HTTPGateways{Client: tlsutil.HTTPClient(gwTLS, 15*time.Second)},
		Audit:       al,
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
		logger.Printf("OIDC provider %s discovered (jwks %s)", disc.Issuer, disc.JWKSURI)
		jwks := iam.NewJWKS(disc.JWKSURI, kc)
		if err := jwks.Refresh(ctx); err != nil {
			return err
		}
		cfg.Validator = &iam.Validator{
			Issuer:          disc.Issuer,
			Audience:        cli.Env("SDP_OIDC_AUDIENCE", "sdp-controller"),
			AuthorizedParty: cli.Env("SDP_OIDC_CLIENT", "sdp-client"),
			Leeway:          5 * time.Second,
			JWKS:            jwks,
		}
		if secret := cli.Env("SDP_KC_ADMIN_CLIENT_SECRET", ""); secret != "" {
			base, realm, err := splitIssuer(disc.Issuer)
			if err != nil {
				return err
			}
			cfg.IAM = controller.KeycloakSessions{
				Admin: &iam.Admin{BaseURL: base, Realm: realm, TokenURL: disc.TokenEndpoint,
					ClientID: cli.Env("SDP_KC_ADMIN_CLIENT_ID", "sdp-controller"), ClientSecret: secret, Client: kc},
				IntrospectURL: disc.IntrospectionEndpoint,
			}
			cfg.Introspect = cli.EnvBool("SDP_INTROSPECT", true)
		} else {
			logger.Printf("SDP_KC_ADMIN_CLIENT_SECRET not set: no token introspection and no Keycloak logout on revocation")
		}
	}

	srv, err := controller.New(cfg)
	if err != nil {
		return err
	}
	tlsCfg, err := tlsutil.ServerConfig(files)
	if err != nil {
		return err
	}
	apiSrv := &http.Server{Addr: cli.Env("SDP_LISTEN", ":8443"), Handler: srv.Handler(), TLSConfig: tlsCfg,
		ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	statusSrv := &http.Server{Addr: cli.Env("SDP_STATUS_LISTEN", "127.0.0.1:8081"), ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(srv.Status(r.URL.Query().Get("verbose") != ""))
		})}

	errCh := make(chan error, 2)
	go func() { errCh <- apiSrv.ListenAndServeTLS("", "") }()
	go func() { errCh <- statusSrv.ListenAndServe() }()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Housekeep(ctx)
			}
		}
	}()
	al.Record(audit.Event{Event: "controller_started", Outcome: "info", Mode: mode})
	logger.Printf("mode %s, listening on %s", mode, apiSrv.Addr)
	_ = os.WriteFile("/tmp/sdp-ready", []byte("ok\n"), 0o644)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(sctx)
	_ = statusSrv.Shutdown(sctx)
	return nil
}

// startSPA closes the public interface and starts fwknopd with the static SPA keys of
// every registered device found in SDP_DEVICE_KEYS_DIR (<device>.keys).
func startSPA(ctx context.Context, pol *policy.Policy, logger *log.Logger) error {
	pubIf, _, err := spa.InterfaceFor(cli.Env("SDP_PUBLIC_SUBNET", "10.233.0.0/24"))
	if err != nil {
		return err
	}
	var trusted []string
	for _, subnet := range cli.List(cli.Env("SDP_TRUSTED_SUBNETS", "10.233.2.0/24")) {
		ifc, _, err := spa.InterfaceFor(subnet)
		if err != nil {
			return err
		}
		trusted = append(trusted, ifc)
	}
	fw := spa.Firewall{Run: spa.ExecRunner}
	if err := fw.DefaultDrop(ctx, trusted); err != nil {
		return err
	}
	port := cli.EnvInt("SDP_LISTEN_PORT", 8443)
	keysDir := cli.Env("SDP_DEVICE_KEYS_DIR", "/etc/sdp/devices")
	var stanzas []spa.Stanza
	ids := make([]string, 0, len(pol.Devices))
	for id := range pol.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b, err := os.ReadFile(filepath.Join(keysDir, id+".keys"))
		if err != nil {
			logger.Printf("device %s has no SPA keys in %s, skipped", id, keysDir)
			continue
		}
		kf, err := spa.ParseKeyFile(b)
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		stanzas = append(stanzas, spa.Stanza{ID: id, Source: "ANY", OpenPorts: []string{fmt.Sprintf("tcp/%d", port)},
			KeyBase64: kf.KeyBase64, HMACKeyBase64: kf.HMACKeyBase64,
			AccessTimeout: cli.EnvInt("SDP_SPA_ACCESS_TIMEOUT", 30)})
	}
	d := spa.NewDaemon(spa.DaemonConfig{Dir: "/run/fwknop", Interface: pubIf, Logger: log.New(os.Stderr, "[fwknopd] ", log.LstdFlags)})
	if err := d.Start(ctx); err != nil {
		return err
	}
	if len(stanzas) > 0 {
		if err := d.Set(ctx, stanzas...); err != nil {
			return err
		}
	}
	logger.Printf("SPA: %s dark (default drop), fwknopd with %d device stanzas; trusted interfaces %v", pubIf, len(stanzas), trusted)
	go func() { <-ctx.Done(); d.Stop() }()
	return nil
}

// splitIssuer turns https://host:port/realms/<realm> into the base URL and the realm.
func splitIssuer(issuer string) (string, string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", "", err
	}
	i := strings.Index(u.Path, "/realms/")
	if i < 0 {
		return "", "", fmt.Errorf("issuer %s is not a Keycloak realm URL", issuer)
	}
	realm := strings.Trim(u.Path[i+len("/realms/"):], "/")
	u.Path = u.Path[:i]
	return strings.TrimRight(u.String(), "/"), realm, nil
}

func status(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	sessions := fs.Bool("sessions", false, "list sessions")
	asJSON := fs.Bool("json", false, "print JSON")
	addr := fs.String("addr", cli.Env("SDP_STATUS_LISTEN", "127.0.0.1:8081"), "status address")
	_ = fs.Parse(args)
	u := "http://" + *addr + "/"
	if *sessions || *asJSON {
		u += "?verbose=1"
	}
	resp, err := http.Get(u) //nolint:gosec // local status port
	if err != nil {
		cli.Fatalf(1, "status: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if *asJSON {
		os.Stdout.Write(body)
		return
	}
	var st controller.Status
	if err := json.Unmarshal(body, &st); err != nil {
		cli.Fatalf(1, "status: %v", err)
	}
	fmt.Printf("mode: %s   gateways: %d   active sessions: %d\n", st.Mode, len(st.Gateways), st.ActiveSessions)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, g := range st.Gateways {
		fmt.Fprintf(tw, "  gateway\t%s\t%s\tspa udp/%d\tproxy tcp/%d\n", g.ID, g.PublicAddr, g.SPAPort, g.ProxyPort)
	}
	if *sessions {
		for _, s := range st.Sessions {
			who := s.Device
			if s.Username != "" {
				who += " (" + s.Username + ")"
			}
			fmt.Fprintf(tw, "  session\t%s\t%s\t%s\t%s\t%s\n", s.SessionID, who, s.Service, s.State, s.EndReason)
		}
	}
	tw.Flush()
}
