// Package passgen generates random passwords that satisfy site rules.
//
// Rules use the "passwordrules" syntax sites publish on password fields
// (https://developer.apple.com/password-rules/), for example
// "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [-_!]".
// browser-extension/passgen.js implements the same rules.
package passgen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Character classes.
const (
	Lower   = "abcdefghijklmnopqrstuvwxyz"
	Upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digit   = "0123456789"
	Special = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	// DefaultSymbols avoids quotes, backslashes and brackets that some sites
	// and shells mishandle.
	DefaultSymbols = "!@#$%^&*-_=+.?"
)

// DefaultLength is used when rules do not force another length.
const DefaultLength = 20

// Policy describes what a generated password must look like.
type Policy struct {
	Length         int      // desired length; clamped to MinLength..MaxLength
	MinLength      int      // 0 = none
	MaxLength      int      // 0 = none
	Required       []string // each entry: at least one character from this set
	Allowed        string   // every character comes from this set (plus Required)
	MaxConsecutive int      // 0 = unlimited identical characters in a row
}

// Default is a strong policy for sites without rules.
func Default() Policy {
	return Policy{
		Length:   DefaultLength,
		Required: []string{Lower, Upper, Digit, DefaultSymbols},
		Allowed:  Lower + Upper + Digit + DefaultSymbols,
	}
}

// ParseRules parses a passwordrules string. Unknown properties are ignored,
// as the specification requires.
func ParseRules(rules string) (Policy, error) {
	p := Policy{Length: DefaultLength}
	sawClass := false
	for _, part := range strings.Split(rules, ";") {
		name, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "minlength", "maxlength", "max-consecutive":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return Policy{}, fmt.Errorf("invalid %s %q", name, value)
			}
			switch name {
			case "minlength":
				p.MinLength = n
			case "maxlength":
				p.MaxLength = n
			default:
				p.MaxConsecutive = n
			}
		case "required", "allowed":
			set, err := parseClasses(value)
			if err != nil {
				return Policy{}, err
			}
			sawClass = true
			if name == "required" {
				p.Required = append(p.Required, set)
			}
			p.Allowed = union(p.Allowed, set)
		}
	}
	if !sawClass {
		d := Default()
		p.Required, p.Allowed = d.Required, d.Allowed
	}
	return p, nil
}

func parseClasses(value string) (string, error) {
	var set string
	for value = strings.TrimSpace(value); value != ""; value = strings.TrimSpace(value) {
		value = strings.TrimLeft(value, ", ")
		if value == "" {
			break
		}
		if value[0] == '[' {
			end := strings.LastIndex(value, "]")
			if end < 1 {
				return "", errors.New("unterminated custom character class")
			}
			set = union(set, value[1:end])
			value = value[end+1:]
			continue
		}
		word, rest, _ := strings.Cut(value, ",")
		value = rest
		switch strings.TrimSpace(strings.ToLower(word)) {
		case "lower":
			set = union(set, Lower)
		case "upper":
			set = union(set, Upper)
		case "digit":
			set = union(set, Digit)
		case "special":
			set = union(set, Special)
		case "ascii-printable", "unicode":
			set = union(set, Lower+Upper+Digit+Special)
		}
	}
	return set, nil
}

// Generate returns a password satisfying p.
func Generate(p Policy) (string, error) {
	length := p.Length
	if length <= 0 {
		length = DefaultLength
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		length = p.MaxLength
	}
	if length < p.MinLength {
		length = p.MinLength
	}
	allowed := p.Allowed
	for _, r := range p.Required {
		allowed = union(allowed, r)
	}
	if allowed == "" {
		return "", errors.New("policy allows no characters")
	}
	required := make([]string, 0, len(p.Required))
	for _, r := range p.Required {
		if r != "" {
			required = append(required, r)
		}
	}
	if len(required) > length {
		return "", fmt.Errorf("length %d is too short for %d required character classes", length, len(required))
	}
	for attempt := 0; attempt < 10000; attempt++ {
		b := make([]byte, length)
		for i := range b {
			c, err := pick(allowed)
			if err != nil {
				return "", err
			}
			b[i] = c
		}
		if satisfies(string(b), required, p.MaxConsecutive) {
			return string(b), nil
		}
	}
	return "", errors.New("could not satisfy the password rules; relax them and retry")
}

func satisfies(pw string, required []string, maxConsecutive int) bool {
	for _, set := range required {
		if !strings.ContainsAny(pw, set) {
			return false
		}
	}
	if maxConsecutive > 0 {
		run := 1
		for i := 1; i < len(pw); i++ {
			if pw[i] == pw[i-1] {
				run++
				if run > maxConsecutive {
					return false
				}
			} else {
				run = 1
			}
		}
	}
	return true
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

// union returns a+b without duplicate characters, keeping only printable ASCII.
func union(a, b string) string {
	var sb strings.Builder
	seen := map[rune]bool{}
	for _, r := range a + b {
		if r < 0x21 || r > 0x7e || seen[r] {
			continue
		}
		seen[r] = true
		sb.WriteRune(r)
	}
	return sb.String()
}
