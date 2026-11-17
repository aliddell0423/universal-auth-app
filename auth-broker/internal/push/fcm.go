package push

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// FCMSender delivers notifications through the Firebase Cloud Messaging HTTP
// v1 API using a service account. It implements Sender.
type FCMSender struct {
	projectID string
	email     string
	key       *rsa.PrivateKey
	tokenURI  string
	sendURL   string
	http      *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// serviceAccount mirrors the fields of a Firebase Admin SDK service account
// JSON file.
type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// NewFCMSenderFromFile loads a service account JSON file.
func NewFCMSenderFromFile(path string) (*FCMSender, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sa serviceAccount
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("parse service account: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("service account missing project_id, client_email or private_key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("service account private_key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse service account private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("service account key is %T, want RSA", key)
	}
	return &FCMSender{
		projectID: sa.ProjectID,
		email:     sa.ClientEmail,
		key:       rsaKey,
		tokenURI:  sa.TokenURI,
		sendURL:   "https://fcm.googleapis.com/v1/projects/" + sa.ProjectID + "/messages:send",
		http:      &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// SendCredentialRequest sends a high-priority data+notification message. The
// payload carries only the request ID; the device fetches the real request
// from the broker.
func (s *FCMSender) SendCredentialRequest(ctx context.Context, installationID, requestID string) error {
	token, err := s.accessToken(ctx)
	if err != nil {
		return err
	}
	body := map[string]any{
		"message": map[string]any{
			"token": installationID,
			"data": map[string]string{
				KeyType:      TypeCredentialRequest,
				KeyRequestID: requestID,
			},
			"android": map[string]any{
				"priority": "HIGH",
				"notification": map[string]string{
					"title": "Universal Auth",
					"body":  "A credential release is waiting for approval",
				},
			},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := s.sendURL
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		// FCM error bodies can echo the token; strip it before logging.
		msg := strings.ReplaceAll(string(respBody), installationID, "<redacted>")
		return fmt.Errorf("fcm send: status %d: %s", resp.StatusCode, msg)
	}
	return nil
}

// accessToken returns a cached OAuth2 access token, refreshing when needed.
func (s *FCMSender) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.tokenExp.Add(-2*time.Minute)) {
		return s.token, nil
	}
	token, exp, err := s.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	s.token, s.tokenExp = token, exp
	return token, nil
}

func (s *FCMSender) fetchToken(ctx context.Context) (string, time.Time, error) {
	now := time.Now()
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	claims, _ := json.Marshal(map[string]any{
		"iss":   s.email,
		"scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud":   s.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	unsigned := header + "." + b64url(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", time.Time{}, err
	}
	assertion := unsigned + "." + b64url(sig)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("oauth token: status %d: %s", resp.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", time.Time{}, errors.New("oauth token: malformed response")
	}
	exp := now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.ExpiresIn == 0 {
		exp = now.Add(55 * time.Minute)
	}
	return tr.AccessToken, exp, nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
