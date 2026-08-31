package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
)

type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, traceID string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if traceID != "" {
		req.Header.Set("X-Universal-Auth-Trace-ID", traceID)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

func (c *Client) Ready(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/readyz", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return apierror.FromResponse(resp, "broker.readyz", "UA-BROKER-009")
}

func (c *Client) GetTrustedDevice(ctx context.Context, traceID string) (TrustedDevice, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/devices/trusted", nil, traceID)
	if err != nil {
		return TrustedDevice{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return TrustedDevice{}, apierror.New(
			"UA-BROKER-001",
			"broker.trusted_device",
			"No trusted Pixel device is registered with the broker.",
			"Run 'authctl pair' to register this Pixel.",
			false,
		)
	}
	if resp.StatusCode != http.StatusOK {
		return TrustedDevice{}, apierror.FromResponse(resp, "broker.trusted_device", "UA-BROKER-004")
	}
	var td TrustedDevice
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
		return TrustedDevice{}, err
	}
	return td, nil
}

func (c *Client) GetTrustedDesktop(ctx context.Context, traceID string) (TrustedDesktop, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/desktops/trusted", nil, traceID)
	if err != nil {
		return TrustedDesktop{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return TrustedDesktop{}, apierror.New(
			"UA-BROKER-002",
			"broker.trusted_desktop",
			"No trusted desktop is registered with the broker.",
			"Run 'authctl desktop-register' to register this Fedora desktop.",
			false,
		)
	}
	if resp.StatusCode != http.StatusOK {
		return TrustedDesktop{}, apierror.FromResponse(resp, "broker.trusted_desktop", "UA-BROKER-004")
	}
	var td TrustedDesktop
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
		return TrustedDesktop{}, err
	}
	return td, nil
}

func (c *Client) RegisterDesktop(ctx context.Context, td TrustedDesktop, traceID string) error {
	payload, _ := json.Marshal(td)
	resp, err := c.do(ctx, http.MethodPost, "/v1/desktops", bytes.NewReader(payload), traceID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	return apierror.FromResponse(resp, "broker.desktop_register", "UA-BROKER-005")
}

func (c *Client) CreateRequest(ctx context.Context, r CreateRequest, traceID string) (Request, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return Request{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/requests", bytes.NewReader(payload), traceID)
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Request{}, apierror.FromResponse(resp, "broker.create_request", "UA-BROKER-006")
	}
	var req Request
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func (c *Client) GetRequest(ctx context.Context, id, traceID string) (Request, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/requests/"+id, nil, traceID)
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Request{}, apierror.New(
			"UA-BROKER-003",
			"broker.request_fetch",
			"The requested broker transaction was not found.",
			"The request may have expired. Try again.",
			false,
		)
	}
	if resp.StatusCode != http.StatusOK {
		return Request{}, apierror.FromResponse(resp, "broker.request_fetch", "UA-BROKER-007")
	}
	var req Request
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func (c *Client) AttachReleaseRequest(ctx context.Context, id string, req ReleaseRequest, traceID string) (Request, error) {
	payload, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost, "/v1/requests/"+id+"/release-request", bytes.NewReader(payload), traceID)
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Request{}, apierror.FromResponse(resp, "broker.attach_release", "UA-BROKER-008")
	}
	var r Request
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Request{}, err
	}
	return r, nil
}

func (c *Client) ValidatePendingResponse(req Request, want CreateRequest) error {
	if req.Status != "pending" {
		return fmt.Errorf("expected status pending, got %s", req.Status)
	}
	if req.ID == "" {
		return fmt.Errorf("request id is empty")
	}
	if req.Source != want.Source || req.Kind != want.Kind || req.Resource != want.Resource || req.Message != want.Message {
		return fmt.Errorf("broker returned unexpected request fields")
	}
	if req.ClientNonce != want.ClientNonce {
		return fmt.Errorf("broker returned unexpected client_nonce")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if err != nil {
		return fmt.Errorf("challenge is not valid unpadded Base64URL: %w", err)
	}
	if len(challenge) != 32 {
		return fmt.Errorf("challenge must be 32 bytes, got %d", len(challenge))
	}
	return nil
}

func PublicKeyFingerprint(publicKey string) string {
	der, _ := base64.StdEncoding.DecodeString(publicKey)
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:])
}
