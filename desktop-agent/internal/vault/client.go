package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
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

func (c *Client) do(ctx context.Context, method, path string, body []byte, traceID string) (*http.Response, error) {
	var bodyR io.Reader
	if body != nil {
		bodyR = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyR)
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
	return apierror.FromResponse(resp, "vault.readyz", "UA-VAULT-004")
}

func (c *Client) CredentialExists(ctx context.Context, resource, traceID string) (bool, error) {
	u := "/v1/credentials/exists?resource=" + url.QueryEscape(resource)
	resp, err := c.do(ctx, http.MethodGet, u, nil, traceID)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, apierror.FromResponse(resp, "vault.exists", "UA-VAULT-004")
	}
	var out ExistsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Exists, nil
}

func (c *Client) GetPackage(ctx context.Context, resource, traceID string) (*vaultcrypto.Package, error) {
	return c.GetPackageKind(ctx, resource, "", traceID)
}

// GetPackageKind fetches a package by resource, restricted to kind when it
// is non-empty. Use it when a name may exist under more than one kind.
func (c *Client) GetPackageKind(ctx context.Context, resource, kind, traceID string) (*vaultcrypto.Package, error) {
	u := "/v1/credentials/package?resource=" + url.QueryEscape(resource)
	if kind != "" {
		u += "&kind=" + url.QueryEscape(kind)
	}
	return c.getPackage(ctx, u, traceID)
}

// GetPackageAccount fetches the package for one account of a resource.
func (c *Client) GetPackageAccount(ctx context.Context, resource, kind, account, traceID string) (*vaultcrypto.Package, error) {
	u := "/v1/credentials/package?resource=" + url.QueryEscape(resource) + "&account=" + url.QueryEscape(account)
	if kind != "" {
		u += "&kind=" + url.QueryEscape(kind)
	}
	return c.getPackage(ctx, u, traceID)
}

// GetPackageByID fetches a package by credential ID.
func (c *Client) GetPackageByID(ctx context.Context, id, traceID string) (*vaultcrypto.Package, error) {
	return c.getPackage(ctx, "/v1/credentials/"+url.PathEscape(id), traceID)
}

func (c *Client) getPackage(ctx context.Context, u, traceID string) (*vaultcrypto.Package, error) {
	resp, err := c.do(ctx, http.MethodGet, u, nil, traceID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apierror.FromResponse(resp, "vault.package_fetch", "UA-VAULT-004")
	}
	var pkg vaultcrypto.Package
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

func (c *Client) CreatePackage(ctx context.Context, pkg *vaultcrypto.Package, traceID string) error {
	body, err := json.Marshal(pkg)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/credentials", body, traceID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return apierror.FromResponse(resp, "vault.package_create", "UA-VAULT-005")
	}
	return nil
}

// List returns metadata for all stored packages. No secret material is
// included in the response.
func (c *Client) List(ctx context.Context, traceID string) ([]CredentialMeta, error) {
	return c.list(ctx, "/v1/credentials", traceID)
}

// ListResource returns metadata for every account stored for resource.
func (c *Client) ListResource(ctx context.Context, resource, kind, traceID string) ([]CredentialMeta, error) {
	u := "/v1/credentials?resource=" + url.QueryEscape(resource)
	if kind != "" {
		u += "&kind=" + url.QueryEscape(kind)
	}
	return c.list(ctx, u, traceID)
}

func (c *Client) list(ctx context.Context, u, traceID string) ([]CredentialMeta, error) {
	resp, err := c.do(ctx, http.MethodGet, u, nil, traceID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apierror.FromResponse(resp, "vault.list", "UA-VAULT-004")
	}
	var out []CredentialMeta
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReplacePackage overwrites credential id with pkg. approval is the
// Pixel-approved vault_write request authorising this exact write.
func (c *Client) ReplacePackage(ctx context.Context, id string, pkg *vaultcrypto.Package, approval *broker.Request, traceID string) error {
	body, err := json.Marshal(map[string]any{"package": pkg, "approval": approval})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPut, "/v1/credentials/"+url.PathEscape(id), body, traceID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apierror.FromResponse(resp, "vault.package_update", "UA-VAULT-011")
	}
	return nil
}

// DeletePackage removes credential id. approval is the Pixel-approved
// vault_write request authorising the delete.
func (c *Client) DeletePackage(ctx context.Context, id string, approval *broker.Request, traceID string) error {
	body, err := json.Marshal(map[string]any{"approval": approval})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodDelete, "/v1/credentials/"+url.PathEscape(id), body, traceID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return apierror.FromResponse(resp, "vault.package_delete", "UA-VAULT-006")
	}
	return nil
}
