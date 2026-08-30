package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

var ErrNotFound = errors.New("credential not found for origin")

type ExistsResponse struct {
	Exists bool `json:"exists"`
}

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

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var bodyR io.Reader
	if body != nil {
		bodyR = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyR)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

func (c *Client) CredentialExists(ctx context.Context, origin string) (bool, error) {
	u := "/v1/credentials/exists?origin=" + url.QueryEscape(origin)
	resp, err := c.do(ctx, http.MethodGet, u, nil)
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

func (c *Client) GetPackage(ctx context.Context, origin string) (*vaultcrypto.Package, error) {
	u := "/v1/credentials/package?origin=" + url.QueryEscape(origin)
	resp, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var pkg vaultcrypto.Package
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

func (c *Client) CreatePackage(ctx context.Context, pkg *vaultcrypto.Package) error {
	body, err := json.Marshal(pkg)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/credentials", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) DeletePackage(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/credentials/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
