// Command sdp-client is the SDP Initiating Host (IH).
//
//	sdp-client login                       IAM login only (password + TOTP), print the token claims
//	sdp-client connect SERVICE             full flow: IAM -> SPA + mTLS to the controller -> SPA to the AHs -> first request
//	sdp-client get PATH                    one request on the saved session
//	sdp-client proxy [-listen ADDR]        local HTTP forwarder for the saved session (curl, browsers, hey, ab)
//	sdp-client load                        closed-loop synthetic workload on the saved session
//	sdp-client bench SERVICE               repeated connection set-ups + workload, JSON for scripts/bench
//	sdp-client disconnect                  end the saved session
//
// Configuration comes from SDP_* environment variables (see docs/components.md). In the
// lab the user's password and TOTP secret are provided as environment variables so the
// scripts can run without a person: a lab-only shortcut for "the user types the password
// and the code shown by an authenticator app".
//
// Exit codes: 0 ok, 1 error, 2 IAM login refused, 3 controller denied, 4 data channel refused.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/cli"
	"github.com/antoniopaya22/iam-ids-sdp/internal/client"
)

const (
	exitError      = 1
	exitIAM        = 2
	exitController = 3
	exitData       = 4
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "login":
		cmdLogin(args)
	case "connect":
		cmdConnect(args)
	case "get":
		cmdGet(args)
	case "proxy":
		cmdProxy(args)
	case "load":
		cmdLoad(args)
	case "bench":
		cmdBench(args)
	case "disconnect":
		cmdDisconnect(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sdp-client login|connect SERVICE|get PATH|proxy|load|bench SERVICE|disconnect [flags]")
	os.Exit(exitError)
}

func mode() string { return cli.Env("SDP_MODE", api.ModeTraditional) }

func newClient() *client.Client {
	c, err := client.New(client.Config{
		Mode:           mode(),
		DeviceDir:      cli.Env("SDP_TLS_DIR", "/etc/sdp/tls"),
		ControllerHost: cli.Env("SDP_CONTROLLER", "controller"),
		ControllerPort: cli.EnvInt("SDP_CONTROLLER_PORT", 8443),
		ControllerSPA:  cli.EnvBool("SDP_CONTROLLER_SPA", true),
		Issuer:         cli.Env("SDP_OIDC_ISSUER", "https://keycloak:8443/realms/sdp"),
		ClientID:       cli.Env("SDP_OIDC_CLIENT", "sdp-client"),
		GatewayName:    cli.Env("SDP_GATEWAY_NAME", "sdp-gateway"),
	})
	if err != nil {
		cli.Fatalf(exitError, "sdp-client: %v", err)
	}
	return c
}

// credFlags registers the credential flags shared by several commands.
type credFlags struct {
	noOTP   *bool
	noLogin *bool
}

func addCredFlags(fs *flag.FlagSet) credFlags {
	return credFlags{
		noOTP:   fs.Bool("no-otp", false, "do not send the TOTP code (MFA must then refuse the login)"),
		noLogin: fs.Bool("no-login", false, "do not log in to the IAM: request the session without a token"),
	}
}

func (f credFlags) credentials() client.Credentials {
	cr := client.Credentials{Username: cli.Env("SDP_USERNAME", ""), Password: os.Getenv("SDP_PASSWORD"),
		TOTPSecret: os.Getenv("SDP_OTP_SECRET")}
	if *f.noOTP {
		cr.TOTPSecret = ""
	}
	if *f.noLogin {
		cr.Username = ""
	}
	return cr
}

func sessionPath(fs *flag.FlagSet) *string {
	return fs.String("session-file", cli.Env("SDP_SESSION_FILE", "/tmp/sdp-session.json"), "where the session is saved")
}

// ---------------------------------------------------------------- login

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	cf := addCredFlags(fs)
	printToken := fs.Bool("print-token", false, "print the raw access token")
	_ = fs.Parse(args)
	cr := cf.credentials()
	if cr.Username == "" {
		cli.Fatalf(exitError, "login: SDP_USERNAME is not set")
	}
	start := time.Now()
	tok, n, err := newClient().Login(context.Background(), cr)
	if err != nil {
		cli.Fatalf(exitIAM, "login refused: %v", err)
	}
	if *printToken {
		fmt.Println(tok)
		return
	}
	cl := decodeClaims(tok)
	fmt.Printf("logged in as %v  realm roles %v  aud %v  expires %s  (%.0f ms, %d bytes)\n",
		cl["preferred_username"], realmRoles(cl), cl["aud"], expiry(cl), ms(time.Since(start)), n)
}

// ---------------------------------------------------------------- connect

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	cf := addCredFlags(fs)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	sp := sessionPath(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		cli.Fatalf(exitError, "usage: sdp-client connect SERVICE")
	}
	service := fs.Arg(0)
	c := newClient()
	res, err := c.Connect(context.Background(), service, cf.credentials())
	if *asJSON {
		res.Token = ""
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		printResult(res)
	}
	if err != nil {
		exitFor(err)
	}
	sf := client.SessionFile{Session: res.Session, Token: res.Token, Username: res.Username, Device: res.Session.Device}
	if err := sf.Save(*sp); err != nil {
		cli.Fatalf(exitError, "save session: %v", err)
	}
	for _, st := range res.Status {
		if st != http.StatusOK {
			os.Exit(exitData)
		}
	}
}

func printResult(r *client.Result) {
	t, b := r.Timings, r.Bytes
	if mode() == api.ModeProposed {
		if t.Token > 0 || r.Token != "" {
			fmt.Printf("  1. IAM login (password + TOTP)      %7.1f ms  %6d B\n", t.Token, b.Token)
		}
	}
	if t.ControllerSPA > 0 {
		fmt.Printf("  2. SPA to the controller            %7.1f ms  %6d B\n", t.ControllerSPA, b.ControllerSPA)
	}
	if t.Controller > 0 {
		fmt.Printf("  3. mTLS session request             %7.1f ms  %6d B\n", t.Controller, b.Controller)
	}
	if r.Session.SessionID == "" {
		return
	}
	fmt.Printf("  4. SPA to %d accepting host(s)       %7.1f ms  %6d B\n", len(r.Session.Grants), t.GatewaySPA, b.GatewaySPA)
	fmt.Printf("  5. first request %-18s %7.1f ms  %6d B\n", r.Session.Path, t.FirstRequest, b.FirstRequest)
	fmt.Printf("  session %s  mode %s  device %s", r.Session.SessionID, r.Session.Mode, r.Session.Device)
	if r.Session.Username != "" {
		fmt.Printf("  user %s", r.Session.Username)
	}
	fmt.Println()
	ids := make([]string, 0, len(r.Status))
	for id := range r.Status {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Printf("  %s -> HTTP %d\n", id, r.Status[id])
	}
	fmt.Printf("  connection set-up %.1f ms, %d bytes on the wire\n", t.Total, b.Total)
}

func exitFor(err error) {
	var denied *client.ErrDenied
	switch {
	case errors.As(err, &denied):
		fmt.Fprintf(os.Stderr, "denied: %v\n", err)
		os.Exit(exitController)
	case strings.HasPrefix(err.Error(), "IAM login"):
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitIAM)
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
}

// ---------------------------------------------------------------- session commands

func loadSession(path string) *client.SessionFile {
	s, err := client.LoadSession(path)
	if err != nil {
		cli.Fatalf(exitError, "no session (run sdp-client connect first): %v", err)
	}
	return s
}

func cmdGet(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	sp := sessionPath(fs)
	noToken := fs.Bool("no-token", false, "send the request without the bearer token")
	_ = fs.Parse(args)
	s := loadSession(*sp)
	path := s.Session.Path
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, err := newClient().Get(ctx, s, path, !*noToken, 0)
	if err != nil {
		fmt.Printf("%s -> no answer (%v)\n", path, err)
		os.Exit(exitData)
	}
	fmt.Printf("%s -> HTTP %d\n", path, status)
	if status/100 != 2 {
		os.Exit(exitData)
	}
}

func cmdProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	sp := sessionPath(fs)
	listen := fs.String("listen", "127.0.0.1:8080", "local listen address (keep it on loopback)")
	_ = fs.Parse(args)
	s := loadSession(*sp)
	srv := &http.Server{Addr: *listen, Handler: newClient().Proxy(s), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("forwarding http://%s -> session %s (%d accepting hosts)", *listen, s.Session.SessionID, len(s.Session.Grants))
	if err := srv.ListenAndServe(); err != nil {
		cli.Fatalf(exitError, "proxy: %v", err)
	}
}

func cmdLoad(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	sp := sessionPath(fs)
	o := loadFlags(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	s := loadSession(*sp)
	r := newClient().Load(context.Background(), s, o.options())
	if *asJSON {
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
		return
	}
	fmt.Printf("%d ok, %d failed in %.1f s: %.1f req/s (%.0f per 10 min), mean %.1f ms, p95 %.1f ms\n",
		r.OK, r.Failed, r.Seconds, r.RequestsPerSec, r.RequestsPer10m, r.MeanLatencyMs, r.P95LatencyMs)
}

type loadOpts struct {
	duration, think *time.Duration
	workers         *int
	path            *string
}

func loadFlags(fs *flag.FlagSet) loadOpts {
	return loadOpts{
		duration: fs.Duration("duration", 30*time.Second, "workload duration"),
		think:    fs.Duration("think", 100*time.Millisecond, "think time between requests of a worker"),
		workers:  fs.Int("workers", 1, "concurrent workers"),
		path:     fs.String("path", "", "request path (default: the service path)"),
	}
}

func (o loadOpts) options() client.LoadOptions {
	return client.LoadOptions{Duration: *o.duration, Think: *o.think, Workers: *o.workers, Path: *o.path}
}

func cmdDisconnect(args []string) {
	fs := flag.NewFlagSet("disconnect", flag.ExitOnError)
	sp := sessionPath(fs)
	_ = fs.Parse(args)
	s := loadSession(*sp)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := newClient().Disconnect(ctx, s.Session.SessionID); err != nil {
		cli.Fatalf(exitError, "disconnect: %v", err)
	}
	_ = os.Remove(*sp)
	fmt.Println("session", s.Session.SessionID, "closed")
}

// ---------------------------------------------------------------- bench

// BenchReport is printed by `sdp-client bench` and consumed by scripts/bench/run.sh.
type BenchReport struct {
	Mode     string            `json:"mode"`
	Device   string            `json:"device"`
	Service  string            `json:"service"`
	Gateways int               `json:"gateways"`
	Runs     []client.Result   `json:"runs"`
	Errors   []string          `json:"errors,omitempty"`
	Load     client.LoadResult `json:"load"`
}

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	cf := addCredFlags(fs)
	runs := fs.Int("runs", 10, "connection set-ups to measure")
	pause := fs.Duration("pause", 500*time.Millisecond, "pause between set-ups")
	o := loadFlags(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		cli.Fatalf(exitError, "usage: sdp-client bench SERVICE")
	}
	c := newClient()
	ctx := context.Background()
	rep := BenchReport{Mode: mode(), Service: fs.Arg(0)}
	var last *client.Result
	for i := 0; i < *runs; i++ {
		if last != nil {
			_ = c.Disconnect(ctx, last.Session.SessionID)
			time.Sleep(*pause)
		}
		res, err := c.Connect(ctx, rep.Service, cf.credentials())
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
			continue
		}
		last = res
		cp := *res
		cp.Token = ""
		rep.Runs = append(rep.Runs, cp)
	}
	if last != nil {
		rep.Device, rep.Gateways = last.Session.Device, len(last.Session.Grants)
		sf := &client.SessionFile{Session: last.Session, Token: last.Token, Username: last.Username}
		if *o.duration > 0 {
			rep.Load = c.Load(ctx, sf, o.options())
		}
		_ = c.Disconnect(ctx, last.Session.SessionID)
	}
	b, _ := json.Marshal(rep)
	fmt.Println(string(b))
	if len(rep.Runs) == 0 {
		os.Exit(exitError)
	}
}

// ---------------------------------------------------------------- helpers

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// decodeClaims reads the payload of a JWT for display only (no verification: the
// controller and the AHs verify the token).
func decodeClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	out := map[string]any{}
	if len(parts) != 3 {
		return out
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func realmRoles(cl map[string]any) []string {
	var roles []string
	if ra, ok := cl["realm_access"].(map[string]any); ok {
		if rs, ok := ra["roles"].([]any); ok {
			for _, r := range rs {
				if s, ok := r.(string); ok && !strings.HasPrefix(s, "default-roles-") && s != "offline_access" && s != "uma_authorization" {
					roles = append(roles, s)
				}
			}
		}
	}
	return roles
}

func expiry(cl map[string]any) string {
	if exp, ok := cl["exp"].(float64); ok {
		return time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
	}
	return "?"
}
