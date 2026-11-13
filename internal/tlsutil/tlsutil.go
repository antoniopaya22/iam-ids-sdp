// Package tlsutil builds the mutual-TLS configurations used between SDP components.
// Every certificate is issued at runtime by the lab CA (pki/gen.sh): the subject CN is the
// component id and the OU its role (device, gateway, controller, ids).
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Files locates a component's credentials: ca.crt, tls.crt and tls.key in Dir.
type Files struct {
	Dir string
}

// CA returns the path of the CA certificate.
func (f Files) CA() string { return filepath.Join(f.Dir, "ca.crt") }

// Cert returns the path of the component certificate.
func (f Files) Cert() string { return filepath.Join(f.Dir, "tls.crt") }

// Key returns the path of the component private key.
func (f Files) Key() string { return filepath.Join(f.Dir, "tls.key") }

// Pool loads a CA bundle.
func Pool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caFile)
	}
	return pool, nil
}

// ServerConfig requires and verifies a client certificate signed by the CA.
func ServerConfig(f Files) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(f.Cert(), f.Key())
	if err != nil {
		return nil, err
	}
	pool, err := Pool(f.CA())
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// ClientConfig presents the component certificate and verifies the server against the
// CA. serverName is checked against the server certificate's DNS SANs, which lets the
// IH dial a gateway by IP while still authenticating it.
func ClientConfig(f Files, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(f.Cert(), f.Key())
	if err != nil {
		return nil, err
	}
	pool, err := Pool(f.CA())
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
}

// HTTPClient returns an HTTP client using cfg.
func HTTPClient(cfg *tls.Config, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &http.Client{Transport: tr, Timeout: timeout}
}

// CAClient returns an HTTP client that only trusts the lab CA (no client certificate),
// used to talk to Keycloak.
func CAClient(caFile string, timeout time.Duration) (*http.Client, error) {
	pool, err := Pool(caFile)
	if err != nil {
		return nil, err
	}
	return HTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, timeout), nil
}

// Peer identifies the authenticated client of a request.
type Peer struct {
	ID   string // certificate CN
	Role string // certificate OU
}

// PeerOf returns the verified client certificate identity of a TLS connection state.
func PeerOf(cs *tls.ConnectionState) (Peer, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return Peer{}, errors.New("no verified client certificate")
	}
	leaf := cs.VerifiedChains[0][0]
	p := Peer{ID: leaf.Subject.CommonName}
	if len(leaf.Subject.OrganizationalUnit) > 0 {
		p.Role = leaf.Subject.OrganizationalUnit[0]
	}
	if p.ID == "" || p.Role == "" {
		return Peer{}, errors.New("client certificate lacks CN or OU")
	}
	return p, nil
}
