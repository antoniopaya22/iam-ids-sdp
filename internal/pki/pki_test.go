package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
	"github.com/antoniopaya22/iam-ids-sdp/internal/tlsutil"
)

func TestIssueAndMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.IssueTo(Member{ID: "controller", Role: "controller", DNSNames: []string{"controller"}}, filepath.Join(dir, "controller")); err != nil {
		t.Fatal(err)
	}
	if err := loaded.IssueTo(Member{ID: "ih-alice", Role: "device"}, filepath.Join(dir, "ih-alice")); err != nil {
		t.Fatal(err)
	}

	// Device bundles carry static SPA keys for the controller.
	b, err := os.ReadFile(filepath.Join(dir, "ih-alice", "spa.keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spa.ParseKeyFile(b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "controller", "spa.keys")); !os.IsNotExist(err) {
		t.Fatal("only devices get SPA keys")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ih-alice", "tls.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", fi.Mode().Perm())
	}

	srvCfg, err := tlsutil.ServerConfig(tlsutil.Files{Dir: filepath.Join(dir, "controller")})
	if err != nil {
		t.Fatal(err)
	}
	cliCfg, err := tlsutil.ClientConfig(tlsutil.Files{Dir: filepath.Join(dir, "ih-alice")}, "controller")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peerCh := make(chan tlsutil.Peer, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			return
		}
		cs := tc.ConnectionState()
		p, _ := tlsutil.PeerOf(&cs)
		peerCh <- p
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := <-peerCh
	if p.ID != "ih-alice" || p.Role != "device" {
		t.Fatalf("peer = %+v", p)
	}
}

func TestIssueValidation(t *testing.T) {
	ca, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []Member{
		{ID: "Bad ID", Role: "device"},
		{ID: "x", Role: "root"},
		{ID: "../etc", Role: "device"},
	} {
		if _, _, err := ca.Issue(m); err == nil {
			t.Errorf("%+v: expected error", m)
		}
	}
	cert, _, err := ca.Issue(Member{ID: "gw", Role: "gateway", IPs: []net.IP{net.ParseIP("10.0.0.1")}, Validity: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.After(ca.Cert.NotAfter) {
		t.Fatal("leaf outlives its CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}
