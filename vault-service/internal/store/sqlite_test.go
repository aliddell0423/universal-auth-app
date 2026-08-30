package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"vault-service/internal/model"
)

func randomKEK(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func tempDB(t *testing.T) (*DB, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.db")
	db, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db, p
}

func TestCreateAndGetByOrigin(t *testing.T) {
	db, _ := tempDB(t)
	defer db.Close()

	kek := randomKEK(t)
	in := model.CredentialInput{
		Origin:   "https://github.com",
		Username: "demo@example.com",
		Password: "fake-password",
	}
	c, err := db.CreateCredential(context.Background(), in, kek)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.Username != in.Username || c.Password != in.Password {
		t.Fatalf("got %v", c)
	}

	got, err := db.GetByOrigin(context.Background(), "https://github.com", kek)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Username != in.Username || got.Password != in.Password || got.Origin != "https://github.com" {
		t.Fatalf("got %v", got)
	}
}

func TestExistsAndList(t *testing.T) {
	db, _ := tempDB(t)
	defer db.Close()

	kek := randomKEK(t)
	_, _ = db.CreateCredential(context.Background(), model.CredentialInput{
		Origin:   "https://github.com",
		Username: "u1",
		Password: "p1",
	}, kek)

	exists, err := db.Exists(context.Background(), "https://github.com")
	if err != nil || !exists {
		t.Fatalf("expected exists, got %v / %v", exists, err)
	}
	exists, _ = db.Exists(context.Background(), "https://other.com")
	if exists {
		t.Fatal("did not expect other origin to exist")
	}

	list, err := db.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v", err)
	}
	if list[0].Origin != "https://github.com" {
		t.Fatalf("list metadata: %v", list[0])
	}
}

func TestDuplicateOrigin(t *testing.T) {
	db, _ := tempDB(t)
	defer db.Close()

	kek := randomKEK(t)
	in := model.CredentialInput{Origin: "https://github.com", Username: "u", Password: "p"}
	_, _ = db.CreateCredential(context.Background(), in, kek)
	_, err := db.CreateCredential(context.Background(), in, kek)
	if err == nil {
		t.Fatal("expected duplicate origin error")
	}
}

func TestUpdateAndDelete(t *testing.T) {
	db, _ := tempDB(t)
	defer db.Close()

	kek := randomKEK(t)
	c, _ := db.CreateCredential(context.Background(), model.CredentialInput{
		Origin:   "https://github.com",
		Username: "old",
		Password: "old",
	}, kek)

	updated, err := db.Update(context.Background(), c.ID, model.CredentialInput{
		Origin:   "https://github.com",
		Username: "new",
		Password: "new",
	}, kek)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Username != "new" || updated.Password != "new" {
		t.Fatalf("got %v", updated)
	}

	if err := db.Delete(context.Background(), c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = db.GetByOrigin(context.Background(), "https://github.com", kek)
	if !isNotFound(err) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	db, p := tempDB(t)
	kek := randomKEK(t)
	_, _ = db.CreateCredential(context.Background(), model.CredentialInput{
		Origin:   "https://github.com",
		Username: "u",
		Password: "p",
	}, kek)
	db.Close()

	db2, err := Open(p)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	c, err := db2.GetByOrigin(context.Background(), "https://github.com", kek)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if c.Username != "u" || c.Password != "p" {
		t.Fatalf("got %v", c)
	}
}

func TestEncryptedColumnsDoNotContainPlaintext(t *testing.T) {
	db, p := tempDB(t)
	defer db.Close()

	kek := randomKEK(t)
	in := model.CredentialInput{Origin: "https://github.com", Username: "plainuser", Password: "plainpass"}
	_, _ = db.CreateCredential(context.Background(), in, kek)

	raw, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer raw.Close()

	for _, secret := range []string{in.Username, in.Password} {
		var found int
		hex := fmt.Sprintf("%x", secret)
		q := "SELECT COUNT(*) FROM credentials WHERE hex(ciphertext) LIKE ? OR hex(wrapped_dek) LIKE ?"
		err := raw.QueryRow(q, "%"+hex+"%", "%"+hex+"%").Scan(&found)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if found > 0 {
			t.Fatalf("plaintext secret %q found in encrypted columns", secret)
		}
	}
}

func isNotFound(err error) bool {
	return err != nil && (err == ErrNotFound)
}
