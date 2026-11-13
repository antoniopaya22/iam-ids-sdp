package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer = "https://keycloak:8443/realms/sdp"
	testAud    = "sdp-controller"
)

type idp struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	fetches atomic.Int32
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, kid: "k1"}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": p.kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())},
			{"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
		}})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) validator() *Validator {
	return &Validator{Issuer: testIssuer, Audience: testAud, AuthorizedParty: "sdp-client",
		Leeway: 5 * time.Second, JWKS: NewJWKS(p.srv.URL, p.srv.Client())}
}

type claimEdit func(jwt.MapClaims)

func (p *idp) token(t *testing.T, edits ...claimEdit) string {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{
		"iss": testIssuer, "aud": []string{testAud, "sdp-gateway"}, "sub": "user-1",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "typ": "Bearer",
		"azp": "sdp-client", "sid": "sess-1", "preferred_username": "alice",
		"realm_access": map[string]any{"roles": []string{"researcher", "offline_access"}},
	}
	for _, e := range edits {
		e(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = p.kid
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidatorAcceptsValidToken(t *testing.T) {
	p := newIDP(t)
	cl, err := p.validator().Validate(context.Background(), p.token(t))
	if err != nil {
		t.Fatal(err)
	}
	if cl.PreferredUsername != "alice" || cl.Subject != "user-1" || cl.SessionID != "sess-1" {
		t.Fatalf("unexpected claims %+v", cl)
	}
	if roles := cl.Roles(); len(roles) != 2 || roles[0] != "researcher" {
		t.Fatalf("roles = %v", roles)
	}
}

func TestValidatorRejections(t *testing.T) {
	p := newIDP(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]string{
		"expired":        p.token(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"no exp":         p.token(t, func(c jwt.MapClaims) { delete(c, "exp") }),
		"wrong issuer":   p.token(t, func(c jwt.MapClaims) { c["iss"] = "https://evil/realms/sdp" }),
		"wrong audience": p.token(t, func(c jwt.MapClaims) { c["aud"] = "account" }),
		"id token":       p.token(t, func(c jwt.MapClaims) { c["typ"] = "ID" }),
		"other client":   p.token(t, func(c jwt.MapClaims) { c["azp"] = "other-client" }),
		"no subject":     p.token(t, func(c jwt.MapClaims) { delete(c, "sub") }),
		"issued in future": p.token(t, func(c jwt.MapClaims) {
			c["iat"] = time.Now().Add(time.Hour).Unix()
		}),
		"bad signature": func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": testIssuer, "aud": testAud,
				"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
			tok.Header["kid"] = p.kid
			s, _ := tok.SignedString(other)
			return s
		}(),
		"alg none": func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": testIssuer, "aud": testAud,
				"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
			tok.Header["kid"] = p.kid
			s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			return s
		}(),
		"HS256 with public key": func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": testIssuer, "aud": testAud,
				"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
			tok.Header["kid"] = p.kid
			s, _ := tok.SignedString(p.key.N.Bytes())
			return s
		}(),
		"garbage": "not.a.jwt",
	}
	v := p.validator()
	for name, tok := range cases {
		if _, err := v.Validate(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: expected ErrInvalidToken, got %v", name, err)
		}
	}
	if _, err := v.Validate(context.Background(), ""); !errors.Is(err, ErrNoToken) {
		t.Errorf("empty token: got %v", err)
	}
}

func TestValidatorMissingRoleClaim(t *testing.T) {
	// A token without realm_access is valid, but carries no roles: RBAC must deny.
	p := newIDP(t)
	cl, err := p.validator().Validate(context.Background(), p.token(t, func(c jwt.MapClaims) { delete(c, "realm_access") }))
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.Roles()) != 0 {
		t.Fatalf("roles = %v, want none", cl.Roles())
	}
}

func TestJWKSRotationAndRateLimit(t *testing.T) {
	p := newIDP(t)
	v := p.validator()
	if _, err := v.Validate(context.Background(), p.token(t)); err != nil {
		t.Fatal(err)
	}
	// Unknown kid right after a fetch: no new download (rate limit).
	before := p.fetches.Load()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": testIssuer, "aud": testAud,
		"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
	tok.Header["kid"] = "unknown"
	s, _ := tok.SignedString(p.key)
	if _, err := v.Validate(context.Background(), s); err == nil {
		t.Fatal("unknown kid accepted")
	}
	if p.fetches.Load() != before {
		t.Fatal("JWKS refetched within MinRefresh")
	}
	// Key rotation: new kid is picked up once the rate limit allows it.
	v.JWKS.MinRefresh = 0
	p.kid = "k2"
	if _, err := v.Validate(context.Background(), p.token(t)); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
}

func TestJWKSECKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "kid": "ec1", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
		}}})
	}))
	defer srv.Close()
	v := &Validator{Issuer: testIssuer, Audience: testAud, JWKS: NewJWKS(srv.URL, srv.Client())}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": testIssuer, "aud": testAud,
		"sub": "x", "exp": time.Now().Add(time.Minute).Unix()})
	tok.Header["kid"] = "ec1"
	s, _ := tok.SignedString(key)
	if _, err := v.Validate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func TestCachingValidatorHonoursExpiry(t *testing.T) {
	p := newIDP(t)
	now := time.Now()
	v := p.validator()
	v.Leeway = 0
	v.Now = func() time.Time { return now }
	cv := NewCachingValidator(v)
	tok := p.token(t, func(c jwt.MapClaims) { c["exp"] = now.Add(30 * time.Second).Unix() })
	if _, err := cv.Validate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := cv.Validate(context.Background(), tok); err != nil {
		t.Fatalf("cached validation failed: %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := cv.Validate(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired cached token accepted: %v", err)
	}
}

func TestDiscoverChecksIssuer(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{Issuer: issuer, JWKSURI: "https://x/certs"})
	}))
	defer srv.Close()
	issuer = srv.URL
	if _, err := Discover(context.Background(), srv.Client(), srv.URL); err != nil {
		t.Fatal(err)
	}
	issuer = "https://evil"
	if _, err := Discover(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("issuer mismatch not detected: %v", err)
	}
}

func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for ts, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		if got := TOTP(secret, time.Unix(ts, 0), 30, 8); got != want {
			t.Errorf("TOTP(%d) = %s, want %s", ts, got, want)
		}
	}
	if got := TOTP(secret, time.Unix(59, 0), 0, 0); got != "287082" {
		t.Errorf("6-digit default = %s", got)
	}
	if Base32Secret([]byte("12345678901234567890")) != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Error("base32 secret")
	}
}

func TestPasswordLoginSendsTOTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("totp") != "123456" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid user credentials"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"abc","expires_in":300}`))
	}))
	defer srv.Close()
	if _, err := PasswordLogin(context.Background(), srv.Client(), srv.URL, "sdp-client", "alice", "pw", ""); err == nil ||
		!strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("login without TOTP: %v", err)
	}
	tr, err := PasswordLogin(context.Background(), srv.Client(), srv.URL, "sdp-client", "alice", "pw", "123456")
	if err != nil || tr.AccessToken != "abc" {
		t.Fatalf("login with TOTP: %v %+v", err, tr)
	}
}
