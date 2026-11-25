package proxy

import (
	"strings"
	"testing"
)

func TestSanitizeExitIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.7", "203.0.113.7", true},
		{" 203.0.113.7\n", "203.0.113.7", true},
		{"2001:DB8::1", "2001:db8::1", true},
		{"", "", false},
		{"203.0.113.7<img src=x onerror=alert(1)>", "", false},
		{"<script>alert(1)</script>", "", false},
		{"999.1.1.1", "", false},
		{"example.com", "", false},
	}
	for _, c := range cases {
		got, ok := sanitizeExitIP(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("sanitizeExitIP(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSanitizeCountryCode(t *testing.T) {
	cases := map[string]string{
		"VN":                        "VN",
		"us":                        "US",
		" de ":                      "DE",
		"":                          "",
		"USA":                       "",
		"U1":                        "",
		"<b":                        "",
		`"><img src=x onerror=a()>`: "",
	}
	for in, want := range cases {
		if got := sanitizeCountryCode(in); got != want {
			t.Errorf("sanitizeCountryCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		"Viet Nam":                      "Viet Nam",
		"  Ho  Chi\tMinh\nCity ":        "Ho Chi Minh City",
		"AT&T Services":                 "AT&T Services",
		"<script>alert(1)</script>":     "scriptalert(1)/script",
		"bad\x00\x1b[31mname\u200b":     "bad[31mname",
		"Thành phố Hồ Chí Minh":         "Thành phố Hồ Chí Minh",
		strings.Repeat("a", 200):        strings.Repeat("a", maxLabelRunes),
		strings.Repeat("é", 200) + "<>": strings.Repeat("é", maxLabelRunes),
	}
	for in, want := range cases {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeErrorBoundsAndCleans(t *testing.T) {
	long := "malformed HTTP response \"\x00\x07" + strings.Repeat("A", 1000) + "\""
	got := sanitizeError(long)
	if n := len([]rune(got)); n > maxErrorRunes {
		t.Fatalf("expected at most %d runes, got %d", maxErrorRunes, n)
	}
	if strings.ContainsAny(got, "\x00\x07") {
		t.Fatalf("control characters survived: %q", got)
	}
}
