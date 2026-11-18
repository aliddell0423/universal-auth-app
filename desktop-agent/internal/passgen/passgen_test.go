package passgen

import (
	"strings"
	"testing"
)

func TestDefaultIsStrong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := Generate(Default())
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != DefaultLength {
			t.Fatalf("length %d", len(pw))
		}
		for _, set := range []string{Lower, Upper, Digit, DefaultSymbols} {
			if !strings.ContainsAny(pw, set) {
				t.Fatalf("%q lacks a character from %q", pw, set)
			}
		}
		if seen[pw] {
			t.Fatal("duplicate password")
		}
		seen[pw] = true
	}
}

func TestParseRulesAndGenerate(t *testing.T) {
	cases := []struct {
		rules  string
		check  func(string) bool
		minLen int
		maxLen int
	}{
		{"minlength: 8; maxlength: 12; required: lower; required: upper; required: digit", func(pw string) bool {
			return strings.ContainsAny(pw, Lower) && strings.ContainsAny(pw, Upper) && strings.ContainsAny(pw, Digit) && !strings.ContainsAny(pw, Special)
		}, 8, 12},
		{"required: digit; maxlength: 6", func(pw string) bool { return strings.Trim(pw, Digit) == "" }, 6, 6},
		{"required: upper; required: [-_!]; allowed: lower; max-consecutive: 1", func(pw string) bool {
			for i := 1; i < len(pw); i++ {
				if pw[i] == pw[i-1] {
					return false
				}
			}
			return strings.ContainsAny(pw, "-_!") && strings.Trim(pw, Lower+Upper+"-_!") == ""
		}, DefaultLength, DefaultLength},
		{"minlength: 32", func(pw string) bool { return strings.ContainsAny(pw, DefaultSymbols) }, 32, 32},
		{"unknown-property: 4; maxlength: 15", func(string) bool { return true }, 15, 15},
	}
	for _, c := range cases {
		p, err := ParseRules(c.rules)
		if err != nil {
			t.Fatalf("%q: %v", c.rules, err)
		}
		for i := 0; i < 50; i++ {
			pw, err := Generate(p)
			if err != nil {
				t.Fatalf("%q: %v", c.rules, err)
			}
			if len(pw) < c.minLen || len(pw) > c.maxLen || !c.check(pw) {
				t.Fatalf("%q produced %q", c.rules, pw)
			}
		}
	}
}

func TestImpossibleRules(t *testing.T) {
	p, _ := ParseRules("maxlength: 2; required: lower; required: upper; required: digit")
	if _, err := Generate(p); err == nil {
		t.Fatal("expected an error for too many required classes")
	}
	if _, err := ParseRules("minlength: x"); err == nil {
		t.Fatal("expected a parse error")
	}
}
