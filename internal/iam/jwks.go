// Package iam integrates the SDP components with an OpenID Connect provider (Keycloak):
// discovery, JWKS-based access-token validation, the IH login (password + TOTP), token
// introspection and session revocation through the Keycloak admin API.
package iam

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKS fetches and caches the signing keys of the identity provider. Unknown key ids
// trigger a refresh (key rotation), rate limited by MinRefresh.
type JWKS struct {
	URL        string
	Client     *http.Client
	MinRefresh time.Duration

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	lastFetch time.Time
}

// NewJWKS returns a cache for the key set at url.
func NewJWKS(url string, client *http.Client) *JWKS {
	if client == nil {
		client = http.DefaultClient
	}
	return &JWKS{URL: url, Client: client, MinRefresh: 10 * time.Second}
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Key returns the public key with the given kid, refreshing the set if needed.
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	fresh := time.Since(j.lastFetch) < j.MinRefresh
	j.mu.RUnlock()
	if ok {
		return k, nil
	}
	if fresh {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	if err := j.Refresh(ctx); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if k, ok := j.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

// Refresh downloads the key set.
func (j *JWKS) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return err
	}
	resp, err := j.Client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: %s returned %s", j.URL, resp.Status)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // Keycloak also publishes encryption keys
		}
		pk, err := k.publicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pk
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable signing keys")
	}
	j.mu.Lock()
	j.keys, j.lastFetch = keys, time.Now()
	j.mu.Unlock()
	return nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64int(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64int(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || n.BitLen() < 2048 {
			return nil, errors.New("weak or invalid RSA key")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported curve %s", k.Crv)
		}
		x, err := b64int(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64int(k.Y)
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) { //nolint:staticcheck // validating untrusted JWK coordinates
			return nil, errors.New("EC point not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("unsupported key type %s", k.Kty)
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// Discovery is the subset of the OpenID Provider metadata the lab uses.
type Discovery struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Discover fetches {issuer}/.well-known/openid-configuration and checks the issuer.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Discovery, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: %s", resp.Status)
	}
	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("oidc discovery: issuer mismatch: got %q, want %q", d.Issuer, issuer)
	}
	if d.JWKSURI == "" {
		return nil, errors.New("oidc discovery: no jwks_uri")
	}
	return &d, nil
}

// DiscoverWithRetry retries discovery until ctx is done (the IdP may still be starting).
func DiscoverWithRetry(ctx context.Context, client *http.Client, issuer string, every time.Duration) (*Discovery, error) {
	for {
		d, err := Discover(ctx, client, issuer)
		if err == nil {
			return d, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(every):
		}
	}
}
