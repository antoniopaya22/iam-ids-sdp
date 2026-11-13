package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenResponse is an OAuth 2.0 token endpoint answer.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	SessionState     string `json:"session_state"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// PasswordLogin authenticates a user with password and TOTP (Keycloak's direct grant
// flow asks for the "totp" parameter when the user has an OTP credential, so both
// factors are verified by Keycloak). The lab uses it so scripts can log in without a
// browser; an interactive IH would use the authorization code flow with PKCE instead.
func PasswordLogin(ctx context.Context, client *http.Client, tokenURL, clientID, username, password, totp string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid"},
	}
	if totp != "" {
		form.Set("totp", totp)
	}
	return postToken(ctx, client, tokenURL, form)
}

// ClientCredentials obtains a token for a confidential client's service account.
func ClientCredentials(ctx context.Context, client *http.Client, tokenURL, clientID, secret string) (*TokenResponse, error) {
	return postToken(ctx, client, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
	})
}

func postToken(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (*TokenResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var tr TokenResponse
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		msg := tr.ErrorDescription
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		return nil, fmt.Errorf("token endpoint: %s: %s (%s)", resp.Status, tr.Error, msg)
	}
	return &tr, nil
}

// Admin talks to Keycloak on behalf of the controller's service account
// (client "sdp-controller", realm-management roles manage-users + view-users).
type Admin struct {
	BaseURL      string // e.g. https://keycloak:8443
	Realm        string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Client       *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (a *Admin) accessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.expires) > 10*time.Second {
		return a.token, nil
	}
	tr, err := ClientCredentials(ctx, a.Client, a.TokenURL, a.ClientID, a.ClientSecret)
	if err != nil {
		return "", err
	}
	a.token = tr.AccessToken
	a.expires = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return a.token, nil
}

func (a *Admin) do(ctx context.Context, method, path string, form url.Values) (*http.Response, error) {
	tok, err := a.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

// LogoutUser removes every SSO session of a user (and the refresh tokens bound to them),
// so the user must authenticate again with MFA.
func (a *Admin) LogoutUser(ctx context.Context, userID string) error {
	resp, err := a.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(a.Realm)+"/users/"+url.PathEscape(userID)+"/logout", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("keycloak logout: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Introspection is the RFC 7662 answer (subset).
type Introspection struct {
	Active   bool   `json:"active"`
	Subject  string `json:"sub"`
	Username string `json:"username"`
	SID      string `json:"sid"`
}

// Introspect asks the IdP whether a token is still active (online check, catches
// tokens of sessions that were logged out). Uses the confidential client credentials.
func (a *Admin) Introspect(ctx context.Context, introspectURL, token string) (*Introspection, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(url.QueryEscape(a.ClientID), url.QueryEscape(a.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := a.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection: %s", resp.Status)
	}
	var in Introspection
	if err := json.NewDecoder(resp.Body).Decode(&in); err != nil {
		return nil, fmt.Errorf("introspection: %w", err)
	}
	return &in, nil
}

// ErrInactive is returned when introspection says the token is no longer active.
var ErrInactive = errors.New("token is not active (session ended or revoked)")
