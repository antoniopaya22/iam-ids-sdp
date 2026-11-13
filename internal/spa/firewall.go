package spa

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Runner executes a command; replaced in tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs commands for real.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed tools
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// Firewall manages the default-drop iptables policy of a host protected by SPA.
type Firewall struct {
	Run Runner
}

// DefaultDrop installs the base policy: drop every inbound packet except loopback,
// replies to connections the host opened, and traffic arriving on trustedIfaces
// (the internal management network). fwknopd inserts its FWKNOP_INPUT jump at the top.
func (f Firewall) DefaultDrop(ctx context.Context, trustedIfaces []string) error {
	cmds := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-P", "FORWARD", "DROP"},
		{"-F", "INPUT"},
		{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, i := range trustedIfaces {
		cmds = append(cmds, []string{"-A", "INPUT", "-i", i, "-j", "ACCEPT"})
	}
	for _, c := range cmds {
		if _, err := f.Run(ctx, "iptables", append([]string{"-w"}, c...)...); err != nil {
			return err
		}
	}
	return nil
}

// RulesFor lists the FWKNOP_INPUT rules (in iptables -S form) that admit ip.
func RulesFor(listing, ip string) []string {
	var out []string
	needle := "-s " + ip + "/32 "
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A FWKNOP_INPUT ") && strings.Contains(line+" ", needle) {
			out = append(out, line)
		}
	}
	return out
}

// RemoveRulesFor deletes the SPA rules that admit ip and drops its tracked connections,
// so packets of already established flows are no longer accepted as ESTABLISHED.
func (f Firewall) RemoveRulesFor(ctx context.Context, ip string) (int, error) {
	if net.ParseIP(ip) == nil {
		return 0, fmt.Errorf("invalid ip %q", ip)
	}
	out, err := f.Run(ctx, "iptables", "-w", "-S", "FWKNOP_INPUT")
	if err != nil {
		return 0, err
	}
	rules := RulesFor(string(out), ip)
	for _, r := range rules {
		args := append([]string{"-w", "-D"}, strings.Fields(strings.TrimPrefix(r, "-A "))...)
		if _, err := f.Run(ctx, "iptables", args...); err != nil {
			return 0, err
		}
	}
	// conntrack exits 1 when nothing matched; that is fine.
	_, _ = f.Run(ctx, "conntrack", "-D", "-s", ip)
	_, _ = f.Run(ctx, "conntrack", "-D", "-d", ip)
	return len(rules), nil
}

// InterfaceFor returns the name of the local interface whose address is in subnet.
func InterfaceFor(subnet string) (name, addr string, err error) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && n.Contains(ipn.IP) {
				return i.Name, ipn.IP.String(), nil
			}
		}
	}
	return "", "", fmt.Errorf("no interface in %s", subnet)
}

// Knock sends one SPA packet with the fwknop client and returns the number of bytes
// sent on the wire (UDP payload) as reported by fwknop.
type Knock struct {
	Server        string
	Port          int
	Access        string // e.g. "tcp/8443"
	AllowIP       string
	KeyBase64     string
	HMACKeyBase64 string
	Binary        string // default "fwknop"
}

// Send runs the fwknop client.
func (k Knock) Send(ctx context.Context) (int, error) {
	bin := k.Binary
	if bin == "" {
		bin = "fwknop"
	}
	port := k.Port
	if port == 0 {
		port = 62201
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := ExecRunner(ctx, bin, "--no-rc-file", "-v",
		"-A", k.Access, "-a", k.AllowIP, "-D", k.Server, "-p", fmt.Sprint(port),
		"--key-base64-rijndael", k.KeyBase64, "--key-base64-hmac", k.HMACKeyBase64,
		"--use-hmac", "--hmac-digest-type", "sha256")
	if err != nil {
		return 0, err
	}
	return parseBytesSent(string(out)), nil
}

func parseBytesSent(out string) int {
	const marker = "bytes sent:"
	i := strings.LastIndex(out, marker)
	if i < 0 {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(strings.TrimSpace(out[i+len(marker):]), "%d", &n)
	return n
}
