package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var ErrNotFound = errors.New("credential not found for origin")

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

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.client.Do(req)
}

func (c *Client) CredentialExists(ctx context.Context, origin string) (bool, error) {
	u := "/v1/credentials/exists?origin=" + url.QueryEscape(origin)
	resp, err := c.do(ctx, http.MethodGet, u)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var out ExistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Exists, nil
}

func (c *Client) GetCredential(ctx context.Context, origin string) (Credential, error) {
	u := "/v1/credentials/by-origin?origin=" + url.QueryEscape(origin)
	resp, err := c.do(ctx, http.MethodGet, u)
	if err != nil {
		return Credential{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Credential{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return Credential{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var out Credential
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Credential{}, err
	}
	return out, nil
}
