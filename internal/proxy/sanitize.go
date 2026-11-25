package proxy

import (
	"net"
	"strings"
	"unicode"
)

// Exit-IP lookups are answered by third-party services reached through a proxy
// the operator does not control, so a hostile proxy can answer with anything.
// Every field is validated here before it is stored or sent to the browser.

const (
	// maxLookupBody caps how much of a lookup response is read.
	maxLookupBody = 64 << 10
	// maxLabelRunes caps free-text fields such as country, city and ISP.
	maxLabelRunes = 64
	// maxErrorRunes caps error messages kept in a test result.
	maxErrorRunes = 300
)

// sanitizeExitIP returns the canonical form of raw when it is an IP address.
func sanitizeExitIP(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// sanitizeCountryCode returns an upper-case ISO 3166-1 alpha-2 code, or "".
func sanitizeCountryCode(raw string) string {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if len(code) != 2 {
		return ""
	}
	for i := 0; i < len(code); i++ {
		if code[i] < 'A' || code[i] > 'Z' {
			return ""
		}
	}
	return code
}

// sanitizeLabel cleans a free-text field: no control or invisible characters,
// no angle brackets, collapsed whitespace, bounded length.
func sanitizeLabel(raw string) string {
	return cleanText(raw, maxLabelRunes, true)
}

func cleanText(raw string, maxRunes int, dropAngles bool) string {
	var b strings.Builder
	count := 0
	lastSpace := true
	for _, r := range raw {
		if count >= maxRunes {
			break
		}
		if unicode.IsSpace(r) {
			r = ' '
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if dropAngles && (r == '<' || r == '>') {
			continue
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}
