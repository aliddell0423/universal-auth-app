package logins

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
)

func entry(id, resource, account string) vault.CredentialMeta {
	return vault.CredentialMeta{CredentialID: id, Kind: "login", Resource: resource, Account: account}
}

func TestMatchLogins(t *testing.T) {
	entries := []vault.CredentialMeta{
		entry("ut", "https://utexas.edu", "ajl5646"),
		entry("ent", "https://enterprise.login.utexas.edu", ""),
		entry("fb", "https://www.facebook.com", ""),
		entry("g1", "https://accounts.google.com", "me@gmail.com"),
		entry("g2", "https://accounts.google.com", "me@work.com"),
		entry("http", "http://utexas.edu", ""),
		entry("evil", "https://utexas.edu.evil.com", ""),
		entry("lan", "http://192.168.1.161:5055", ""),
		entry("port", "https://utexas.edu:8443", ""),
		{CredentialID: "sec", Kind: "secret", Resource: "https://utexas.edu"},
	}
	ids := func(ms []Match) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.CredentialID+":"+m.Match)
		}
		return out
	}
	cases := map[string][]string{
		"https://enterprise.login.utexas.edu": {"ent:exact", "ut:parent"},
		"https://utexas.edu":                  {"ut:exact"},
		"https://facebook.com":                {"fb:exact"},
		"https://m.facebook.com":              nil, // sibling, not parent
		"https://accounts.google.com":         {"g1:exact", "g2:exact"},
		"http://192.168.1.161:5055":           {"lan:exact"},
		"https://evil.com":                    nil,
	}
	for origin, want := range cases {
		got, err := MatchLogins(origin, entries, nil)
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		if !reflect.DeepEqual(ids(got), want) {
			t.Errorf("%s: got %v want %v", origin, ids(got), want)
		}
	}

	aliases := map[string][]string{"https://m.facebook.com": {"https://www.facebook.com"}}
	got, _ := MatchLogins("https://m.facebook.com", entries, aliases)
	if !reflect.DeepEqual(ids(got), []string{"fb:alias"}) {
		t.Fatalf("alias: %v", ids(got))
	}
}

func TestSaveTargets(t *testing.T) {
	got, _ := SaveTargets("https://enterprise.login.utexas.edu/idp/x")
	if got != nil {
		t.Fatal("paths must be rejected")
	}
	got, err := SaveTargets("https://enterprise.login.utexas.edu")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://enterprise.login.utexas.edu", "https://login.utexas.edu", "https://utexas.edu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	got, _ = SaveTargets("http://192.168.0.1")
	if !reflect.DeepEqual(got, []string{"http://192.168.0.1"}) {
		t.Fatalf("ip: %v", got)
	}
}

func TestAliasStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "site-aliases.json")
	s, err := LoadAliases(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Link("https://m.facebook.com/", "https://www.facebook.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Link("https://x.com", "https://x.com"); err == nil {
		t.Fatal("self link must fail")
	}
	r, _ := LoadAliases(path)
	if !reflect.DeepEqual(r.Aliases["https://m.facebook.com"], []string{"https://www.facebook.com"}) {
		t.Fatalf("reloaded: %v", r.Aliases)
	}
	if err := r.Unlink("https://m.facebook.com", "https://www.facebook.com"); err != nil {
		t.Fatal(err)
	}
	if len(r.Aliases) != 0 {
		t.Fatalf("unlink: %v", r.Aliases)
	}
}
