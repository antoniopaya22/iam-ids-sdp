package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/antoniopaya22/iam-ids-sdp/internal/api"
	"github.com/antoniopaya22/iam-ids-sdp/internal/iam"
)

// HTTPGateways pushes sessions to AHs over mTLS (the controller's certificate).
type HTTPGateways struct {
	Client *http.Client
}

// Install implements GatewayClient.
func (h HTTPGateways) Install(ctx context.Context, gw Gateway, s api.GatewaySession) error {
	return h.post(ctx, gw.ControlURL+"/v1/sessions", s)
}

// Revoke implements GatewayClient.
func (h HTTPGateways) Revoke(ctx context.Context, gw Gateway, r api.RevokeRequest) error {
	return h.post(ctx, gw.ControlURL+"/v1/revoke", r)
}

func (h HTTPGateways) post(ctx context.Context, url string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// KeycloakSessions adapts iam.Admin to IAMSessions.
type KeycloakSessions struct {
	Admin         *iam.Admin
	IntrospectURL string
}

// Introspect implements IAMSessions.
func (k KeycloakSessions) Introspect(ctx context.Context, token string) (*iam.Introspection, error) {
	return k.Admin.Introspect(ctx, k.IntrospectURL, token)
}

// LogoutUser implements IAMSessions.
func (k KeycloakSessions) LogoutUser(ctx context.Context, userID string) error {
	return k.Admin.LogoutUser(ctx, userID)
}
