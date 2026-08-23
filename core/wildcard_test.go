package core

import (
	"strings"
	"testing"
	"time"
)

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"repo:org/repo:*", "repo:org/repo:ref:refs/heads/main", true},
		{"repo:org/repo:*", "repo:other/repo:ref:refs/heads/main", false},
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"exact", "exact", true},
		{"exact", "exacts", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		// ":main" is literal: the value below ends "/main", not ":main".
		{"*:main", "repo:org/repo:ref:refs/heads/main", false},
		{"*:main", "repo:org/repo:main", true},
		{"*/main", "repo:org/repo:ref:refs/heads/main", true},
		{"*:main", "repo:org/repo:ref:refs/heads/dev", false},
		// A star in the VALUE is an ordinary character.
		{"*", "*0", true},
		{"*0", "*0", true},
		{"?0", "*0", true},
		{"system:serviceaccount:*:my-sa", "system:serviceaccount:prod:my-sa", true},
		{"system:serviceaccount:*:my-sa", "system:serviceaccount:prod:other", false},
		{"**", "anything", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"*abc", "abc", true},
		{"abc*", "abc", true},
		{"*abc*", "xxabcyy", true},
		// Slashes are ordinary characters here, unlike path.Match.
		{"repo:*/main", "repo:org/repo/main", true},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.pattern, c.value); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

// The old implementation recursed over every split point per star, which is
// exponential. The pattern is a live IAM policy value, so its shape is not this
// code's choice — a pathological one must not stall validation.
func TestWildcardMatchIsLinear(t *testing.T) {
	pattern := strings.Repeat("*a", 20) + "*b"
	value := strings.Repeat("a", 200)

	done := make(chan bool, 1)
	go func() { done <- wildcardMatch(pattern, value) }()

	select {
	case got := <-done:
		if got {
			t.Errorf("wildcardMatch(%q, ...) = true, want false", pattern)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wildcardMatch did not finish in 2s on a pathological pattern")
	}
}

func FuzzWildcardMatch(f *testing.F) {
	f.Add("repo:org/repo:*", "repo:org/repo:ref:refs/heads/main")
	f.Add("*", "")
	f.Add("a?c", "abc")
	f.Add("**a**", "aaa")

	f.Fuzz(func(t *testing.T, pattern, value string) {
		// The invariants: it terminates, and a pattern with no metacharacters
		// behaves exactly like string equality.
		got := wildcardMatch(pattern, value)
		if !strings.ContainsAny(pattern, "*?") && got != (pattern == value) {
			t.Fatalf("literal pattern %q vs %q: got %v, want %v", pattern, value, got, pattern == value)
		}
		// A pattern of only stars matches everything.
		if len(pattern) > 0 && strings.Trim(pattern, "*") == "" && !got {
			t.Fatalf("all-star pattern %q should match %q", pattern, value)
		}
	})
}
