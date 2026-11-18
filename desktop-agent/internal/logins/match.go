package logins

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

// Match types, best first.
const (
	MatchExact  = "exact"  // stored for this origin (or its www. twin)
	MatchAlias  = "alias"  // linked to this origin by the user
	MatchParent = "parent" // stored for a parent domain of this origin
)

// Match is a stored login offered for a page.
type Match struct {
	vault.CredentialMeta
	Match string `json:"match"`
}

// Candidates returns the origins whose stored logins may be offered on
// origin, with their match type. A login saved for https://utexas.edu is
// offered on https://enterprise.login.utexas.edu, never the reverse, and
// never across schemes or ports. www.example.com and example.com are treated
// as the same site. IP-address hosts only match exactly.
func Candidates(origin string) (map[string]string, error) {
	norm, err := vaultcrypto.NormalizeOrigin(origin)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(norm)
	if err != nil {
		return nil, err
	}
	out := map[string]string{norm: MatchExact}
	host, port := u.Hostname(), u.Port()
	if net.ParseIP(host) != nil {
		return out, nil
	}
	build := func(h string) string {
		if port != "" {
			h = net.JoinHostPort(h, port)
		}
		return u.Scheme + "://" + h
	}
	if rest, ok := strings.CutPrefix(host, "www."); ok {
		out[build(rest)] = MatchExact
	} else {
		out[build("www."+host)] = MatchExact
	}
	labels := strings.Split(host, ".")
	// Stop before the last label so a bare TLD never matches.
	for i := 1; i < len(labels)-1; i++ {
		parent := strings.Join(labels[i:], ".")
		if _, seen := out[build(parent)]; !seen {
			out[build(parent)] = MatchParent
		}
	}
	return out, nil
}

// MatchLogins filters entries to the logins offered on origin. aliases maps
// a page origin to resources the user linked to it.
func MatchLogins(origin string, entries []vault.CredentialMeta, aliases map[string][]string) ([]Match, error) {
	cands, err := Candidates(origin)
	if err != nil {
		return nil, err
	}
	norm, _ := vaultcrypto.NormalizeOrigin(origin)
	for _, r := range aliases[norm] {
		if _, ok := cands[r]; !ok {
			cands[r] = MatchAlias
		}
	}
	rank := map[string]int{MatchExact: 0, MatchAlias: 1, MatchParent: 2}
	var out []Match
	for _, e := range entries {
		if e.Kind != vaultcrypto.KindLogin {
			continue
		}
		if m, ok := cands[e.Resource]; ok {
			out = append(out, Match{CredentialMeta: e, Match: m})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Match] != rank[out[j].Match] {
			return rank[out[i].Match] < rank[out[j].Match]
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Account < out[j].Account
	})
	return out, nil
}

// SaveTargets lists the origins a login captured on origin may be saved
// under: the origin itself, then each parent domain (most specific first).
// Saving under a parent makes the login available on all its subdomains.
func SaveTargets(origin string) ([]string, error) {
	norm, err := vaultcrypto.NormalizeOrigin(origin)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(norm)
	out := []string{norm}
	host, port := u.Hostname(), u.Port()
	if net.ParseIP(host) != nil {
		return out, nil
	}
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels)-1; i++ {
		h := strings.Join(labels[i:], ".")
		if port != "" {
			h = net.JoinHostPort(h, port)
		}
		out = append(out, u.Scheme+"://"+h)
	}
	return out, nil
}
