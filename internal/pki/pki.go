// Package pki is the small certificate authority of the lab. It runs once, when the lab
// starts (cmd/sdp-pki, called by lab/pki-bootstrap.sh), and writes every key into a Docker
// volume: nothing is committed to the repository.
//
// One ECDSA P-256 CA issues every component certificate. The subject CN is the component
// id (device id, "controller", "sdp-gateway", "ids", "keycloak") and the first OU its role,
// which the SDP components use to authorize mTLS peers (see tlsutil.PeerOf).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/antoniopaya22/iam-ids-sdp/internal/spa"
)

// Organization written in every subject.
const Organization = "iam-ids-sdp lab"

// Roles a certificate can carry (first OU).
var Roles = map[string]bool{"device": true, "gateway": true, "controller": true, "ids": true, "server": true}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// CA is a loaded certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Member describes a certificate to issue.
type Member struct {
	ID       string
	Role     string
	DNSNames []string
	IPs      []net.IP
	Validity time.Duration
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
}

// NewCA creates a self-signed CA.
func NewCA(commonName string, validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{Organization}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Issue signs a certificate for m and returns it with its private key.
func (ca *CA) Issue(m Member) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if !idRe.MatchString(m.ID) {
		return nil, nil, fmt.Errorf("pki: invalid id %q", m.ID)
	}
	if !Roles[m.Role] {
		return nil, nil, fmt.Errorf("pki: invalid role %q", m.Role)
	}
	if m.Validity <= 0 {
		m.Validity = 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(m.Validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{CommonName: m.ID, Organization: []string{Organization},
			OrganizationalUnit: []string{m.Role}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              m.DNSNames,
		IPAddresses:           m.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// ---------------------------------------------------------------- files

// Save writes ca.crt and ca.key into dir.
func (ca *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.Cert.Raw, 0o644); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, "ca.key"), "PRIVATE KEY", der, 0o600)
}

// LoadCA reads ca.crt and ca.key from dir.
func LoadCA(dir string) (*CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, errors.New("pki: invalid CA files")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: CA key is not ECDSA")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueTo issues m and writes ca.crt, tls.crt and tls.key into dir (the layout
// tlsutil.Files expects). Devices also get spa.keys: their static SPA keys for the
// controller (the controller receives a copy, see lab/pki-bootstrap.sh).
func (ca *CA) IssueTo(m Member, dir string) error {
	cert, key, err := ca.Issue(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.Cert.Raw, 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "tls.crt"), "CERTIFICATE", cert.Raw, 0o644); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "tls.key"), "PRIVATE KEY", der, 0o600); err != nil {
		return err
	}
	if m.Role == "device" {
		k, h := spa.NewKeys()
		body := fmt.Sprintf("KEY_BASE64 %s\nHMAC_KEY_BASE64 %s\n", k, h)
		if err := os.WriteFile(filepath.Join(dir, "spa.keys"), []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
