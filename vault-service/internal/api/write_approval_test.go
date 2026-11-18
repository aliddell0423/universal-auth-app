package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"vault-service/internal/approval"
	"vault-service/internal/model"
	"vault-service/internal/store"
)

// pixel plays the trusted Pixel: it signs vault_write approvals the way the
// broker records them.
type pixel struct {
	priv     *ecdsa.PrivateKey
	spki     string
	deviceID string
	n        int
}

func newPixel(t *testing.T) *pixel {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	return &pixel{priv: priv, spki: base64.StdEncoding.EncodeToString(der), deviceID: hex.EncodeToString(sum[:])}
}

func (p *pixel) approve(t *testing.T, op approval.Op, resource string) *approval.Request {
	t.Helper()
	p.n++
	req := &approval.Request{
		ID:          fmt.Sprintf("req-%d", p.n),
		Source:      "test-desktop",
		Kind:        approval.Kind,
		Resource:    resource,
		Message:     "Change saved login",
		Challenge:   "Y2hhbGxlbmdl",
		ClientNonce: approval.Nonce(op),
		Status:      "approved",
	}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	payload := "universal-auth:v2\n" +
		"request_id=" + b64(req.ID) + "\n" +
		"challenge=" + req.Challenge + "\n" +
		"client_nonce=" + req.ClientNonce + "\n" +
		"decision=" + b64("approved") + "\n" +
		"source=" + b64(req.Source) + "\n" +
		"kind=" + b64(req.Kind) + "\n" +
		"resource=" + b64(req.Resource) + "\n" +
		"message=" + b64(req.Message) + "\n"
	digest := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req.ApprovalProof = &approval.Proof{DeviceID: p.deviceID, Algorithm: "ECDSA_P256_SHA256", Signature: base64.StdEncoding.EncodeToString(sig)}
	return req
}

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func approvalServer(t *testing.T, px *pixel) (*httptest.Server, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	var v *approval.Verifier
	if px != nil {
		if v, err = approval.NewVerifier(px.spki); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(NewServer(db, "test-token", v).Handler())
	t.Cleanup(func() { srv.Close(); db.Close() })
	return srv, db
}

func send(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(method, url, &buf)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func v3Input(t *testing.T, id, resource, account string) model.CredentialPackageInput {
	t.Helper()
	in := newPackageInput(t)
	if id != "" {
		in.CredentialID = id
	}
	in.Origin = ""
	in.Kind = model.KindLogin
	in.Resource = resource
	in.Account = account
	in.CryptoVersion = 3
	return in
}

func TestUpdateRequiresPixelApproval(t *testing.T) {
	px := newPixel(t)
	srv, _ := approvalServer(t, px)
	orig := v3Input(t, "", "https://utexas.edu", "ajl")
	if resp := send(t, http.MethodPost, srv.URL+"/v1/credentials", orig); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	url := srv.URL + "/v1/credentials/" + orig.CredentialID
	upd := v3Input(t, orig.CredentialID, "https://enterprise.login.utexas.edu", "ajl5646")
	op := approval.Op{Op: approval.OpUpdate, CredentialID: orig.CredentialID, Package: &upd}

	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no approval: %d", resp.StatusCode)
	}

	// Approval for a different package must not authorise this one.
	other := upd
	other.Ciphertext = orig.Ciphertext
	wrongOp := approval.Op{Op: approval.OpUpdate, CredentialID: orig.CredentialID, Package: &other}
	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, px.approve(t, wrongOp, "https://utexas.edu"))}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong op: %d", resp.StatusCode)
	}
	// Approval shown for a different site is refused.
	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, px.approve(t, op, "https://evil.example"))}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong site: %d", resp.StatusCode)
	}
	// Approval signed by another key is refused.
	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, newPixel(t).approve(t, op, "https://utexas.edu"))}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign key: %d", resp.StatusCode)
	}
	// Tampered field after signing is refused.
	tampered := px.approve(t, op, "https://utexas.edu")
	tampered.Message = "something else"
	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, tampered)}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered: %d", resp.StatusCode)
	}

	good := px.approve(t, op, "https://utexas.edu")
	resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, good)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approved update: %d", resp.StatusCode)
	}
	var got model.CredentialPackage
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Resource != "https://enterprise.login.utexas.edu" || got.Account != "ajl5646" {
		t.Fatalf("updated: %+v", got)
	}
	if resp := send(t, http.MethodPut, url, replaceBody{Package: upd, Approval: raw(t, good)}); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed approval: %d", resp.StatusCode)
	}
}

func TestDeleteRequiresPixelApproval(t *testing.T) {
	px := newPixel(t)
	srv, db := approvalServer(t, px)
	in := v3Input(t, "", "https://github.com", "")
	send(t, http.MethodPost, srv.URL+"/v1/credentials", in)
	url := srv.URL + "/v1/credentials/" + in.CredentialID

	if resp := send(t, http.MethodDelete, url, deleteBody{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no approval: %d", resp.StatusCode)
	}
	updOp := approval.Op{Op: approval.OpUpdate, CredentialID: in.CredentialID, Package: &in}
	if resp := send(t, http.MethodDelete, url, deleteBody{Approval: raw(t, px.approve(t, updOp, "https://github.com"))}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("update approval used for delete: %d", resp.StatusCode)
	}
	delOp := approval.Op{Op: approval.OpDelete, CredentialID: in.CredentialID}
	if resp := send(t, http.MethodDelete, url, deleteBody{Approval: raw(t, px.approve(t, delOp, "https://github.com"))}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("approved delete: %d", resp.StatusCode)
	}
	if list, _ := db.List(t.Context()); len(list) != 0 {
		t.Fatalf("credential still present: %+v", list)
	}
}

func TestWritesRefusedWithoutApproverKey(t *testing.T) {
	srv, _ := approvalServer(t, nil)
	in := v3Input(t, "", "https://github.com", "")
	send(t, http.MethodPost, srv.URL+"/v1/credentials", in)
	resp := send(t, http.MethodDelete, srv.URL+"/v1/credentials/"+in.CredentialID, deleteBody{})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestListFilterAndGetByID(t *testing.T) {
	srv, _ := approvalServer(t, nil)
	a := v3Input(t, "", "https://accounts.google.com", "me@gmail.com")
	b := v3Input(t, "", "https://accounts.google.com", "me@work.com")
	c := v3Input(t, "", "https://github.com", "")
	for _, in := range []model.CredentialPackageInput{a, b, c} {
		if resp := send(t, http.MethodPost, srv.URL+"/v1/credentials", in); resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: %d", resp.StatusCode)
		}
	}
	resp := send(t, http.MethodGet, srv.URL+"/v1/credentials?resource=https://accounts.google.com&kind=login", nil)
	var list []model.CredentialMeta
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 2 || list[0].Account != "me@gmail.com" {
		t.Fatalf("filtered list: %+v", list)
	}
	if resp := send(t, http.MethodGet, srv.URL+"/v1/credentials/package?resource=https://accounts.google.com&kind=login", nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("ambiguous fetch: %d", resp.StatusCode)
	}
	resp = send(t, http.MethodGet, srv.URL+"/v1/credentials/package?resource=https://accounts.google.com&kind=login&account=me@work.com", nil)
	var pkg model.CredentialPackage
	_ = json.NewDecoder(resp.Body).Decode(&pkg)
	if pkg.CredentialID != b.CredentialID {
		t.Fatalf("fetch by account: %+v", pkg)
	}
	resp = send(t, http.MethodGet, srv.URL+"/v1/credentials/"+c.CredentialID, nil)
	pkg = model.CredentialPackage{}
	_ = json.NewDecoder(resp.Body).Decode(&pkg)
	if resp.StatusCode != http.StatusOK || pkg.Resource != "https://github.com" {
		t.Fatalf("get by id: %d %+v", resp.StatusCode, pkg)
	}
}

// TestWriteCanonicalFixture pins the vault-write canonical form shared with
// desktop-agent/internal/vaultwrite.
func TestWriteCanonicalFixture(t *testing.T) {
	in := model.CredentialPackageInput{
		CredentialID: "00112233445566778899aabbccddeeff", Kind: "login",
		Resource: "https://enterprise.login.utexas.edu", Account: "ajl5646",
		Ciphertext: "Y2lwaGVy", CipherNonce: "bm9uY2U", WrappedDEK: "ZGVr", WrapNonce: "d3JhcA",
		WrapEphemeralPublicKey: "a2V5", PixelVaultKeyID: "pix", CryptoVersion: 3,
	}
	got := approval.Canonical(approval.Op{Op: approval.OpUpdate, CredentialID: in.CredentialID, Package: &in})
	path := filepath.Join("..", "..", "..", "testdata", "contracts", "vault_write_canonical.txt")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical mismatch:\n%s\nwant:\n%s", got, want)
	}
}

// TestBrokerShapedApprovalAccepted sends the approval exactly as the broker
// returns it, with fields the vault does not use.
func TestBrokerShapedApprovalAccepted(t *testing.T) {
	px := newPixel(t)
	srv, _ := approvalServer(t, px)
	in := v3Input(t, "", "https://github.com", "me")
	send(t, http.MethodPost, srv.URL+"/v1/credentials", in)
	op := approval.Op{Op: approval.OpDelete, CredentialID: in.CredentialID}
	a := px.approve(t, op, "https://github.com")
	var m map[string]any
	_ = json.Unmarshal(raw(t, a), &m)
	m["created_at"] = "2026-11-18T03:00:00Z"
	m["decided_at"] = "2026-11-18T03:00:05Z"
	m["trace_id"] = "abc"
	m["release_request"] = nil
	if resp := send(t, http.MethodDelete, srv.URL+"/v1/credentials/"+in.CredentialID, map[string]any{"approval": m}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("broker-shaped approval: %d", resp.StatusCode)
	}
}
