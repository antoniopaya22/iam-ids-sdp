package iam

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the access-token claims the SDP uses.
type Claims struct {
	jwt.RegisteredClaims
	Type              string `json:"typ,omitempty"`
	AuthorizedParty   string `json:"azp,omitempty"`
	SessionID         string `json:"sid,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ACR string `json:"acr,omitempty"`
}

// Roles returns the realm roles carried by the token.
func (c *Claims) Roles() []string { return c.RealmAccess.Roles }

// Validator checks Keycloak access tokens offline: RS256/ES256 signature against the
// JWKS, issuer, audience, expiry (required), token type and, optionally, the client the
// token was issued to (azp).
type Validator struct {
	Issuer          string
	Audience        string
	AuthorizedParty string // empty: any client
	Leeway          time.Duration
	JWKS            *JWKS
	Now             func() time.Time // for tests
}

// Errors returned by Validate (wrapped).
var (
	ErrNoToken      = errors.New("no bearer token")
	ErrInvalidToken = errors.New("invalid token")
)

// Validate parses raw and returns its claims if every check passes.
func (v *Validator) Validate(ctx context.Context, raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrNoToken
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.Leeway),
	}
	if v.Now != nil {
		opts = append(opts, jwt.WithTimeFunc(v.Now))
	}
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		return v.JWKS.Key(ctx, kid)
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.Type != "" && claims.Type != "Bearer" {
		return nil, fmt.Errorf("%w: token type %q is not an access token", ErrInvalidToken, claims.Type)
	}
	if v.AuthorizedParty != "" && claims.AuthorizedParty != v.AuthorizedParty {
		return nil, fmt.Errorf("%w: issued to client %q, want %q", ErrInvalidToken, claims.AuthorizedParty, v.AuthorizedParty)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	return claims, nil
}

// CachingValidator memoises successful validations until the token expires, so an AH
// does not re-verify the RSA signature on every proxied request. Revocation is handled
// separately (revoked session ids), as with any self-contained token.
type CachingValidator struct {
	*Validator
	mu    sync.Mutex
	cache map[[32]byte]*Claims
}

// NewCachingValidator wraps v.
func NewCachingValidator(v *Validator) *CachingValidator {
	return &CachingValidator{Validator: v, cache: map[[32]byte]*Claims{}}
}

// Validate returns cached claims for a token already validated and still unexpired.
func (c *CachingValidator) Validate(ctx context.Context, raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrNoToken
	}
	key := sha256.Sum256([]byte(raw))
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	c.mu.Lock()
	cl, ok := c.cache[key]
	c.mu.Unlock()
	if ok && cl.ExpiresAt != nil && now.Before(cl.ExpiresAt.Add(c.Leeway)) {
		return cl, nil
	}
	cl, err := c.Validator.Validate(ctx, raw)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.cache) > 10000 {
		c.cache = map[[32]byte]*Claims{}
	}
	c.cache[key] = cl
	c.mu.Unlock()
	return cl, nil
}
