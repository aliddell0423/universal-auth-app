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

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

func (c *Client) GetTrustedDevice(ctx context.Context) (TrustedDevice, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/devices/trusted", nil)
	if err != nil {
		return TrustedDevice{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return TrustedDevice{}, fmt.Errorf("no trusted device registered")
	}
	if resp.StatusCode != http.StatusOK {
		return TrustedDevice{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var td TrustedDevice
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
		return TrustedDevice{}, err
	}
	return td, nil
}

func (c *Client) GetTrustedDesktop(ctx context.Context) (TrustedDesktop, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/desktops/trusted", nil)
	if err != nil {
		return TrustedDesktop{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return TrustedDesktop{}, fmt.Errorf("no trusted desktop registered")
	}
	if resp.StatusCode != http.StatusOK {
		return TrustedDesktop{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var td TrustedDesktop
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
		return TrustedDesktop{}, err
	}
	return td, nil
}

func (c *Client) RegisterDesktop(ctx context.Context, td TrustedDesktop) error {
	payload, _ := json.Marshal(td)
	resp, err := c.do(ctx, http.MethodPost, "/v1/desktops", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) CreateRequest(ctx context.Context, r CreateRequest) (Request, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return Request{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/requests", bytes.NewReader(payload))
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Request{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var req Request
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func (c *Client) GetRequest(ctx context.Context, id string) (Request, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/requests/"+id, nil)
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Request{}, fmt.Errorf("request not found")
	}
	if resp.StatusCode != http.StatusOK {
		return Request{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var req Request
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func (c *Client) AttachReleaseRequest(ctx context.Context, id string, req ReleaseRequest) (Request, error) {
	payload, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost, "/v1/requests/"+id+"/release-request", bytes.NewReader(payload))
	if err != nil {
		return Request{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Request{}, fmt.Errorf("HTTP %d", resp.StatusCode)
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
