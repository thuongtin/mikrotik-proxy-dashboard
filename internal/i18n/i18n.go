// Package i18n localizes user-facing API messages.
//
// Catalogs are flat JSON objects (key -> message) embedded from
// locales/<lang>.json. An edition can add its own messages in
// locales/<name>.<lang>.json; they are merged into <lang>, and a key defined
// twice is an error. English is the reference catalog: a key missing from
// another language falls back to English, then to the key itself.
//
// Messages use named placeholders such as {count} or {err}. Counted messages
// may have plural variants with the suffixes _one, _few, _many and _other,
// selected by the "count" argument using CLDR plural rules.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
)

// CookieName is the cookie that carries the language chosen in the UI.
const CookieName = "pgw_lang"

// Default is the language used when nothing else matches. Its catalog is the
// reference every other catalog is checked against.
const Default = "en"

// Supported lists the language codes the API accepts, in display order.
var Supported = []string{"en", "vi", "zh", "ru", "ko"}

// PluralSuffixes are the plural variant suffixes, in lookup preference order
// after the category chosen for the count.
var PluralSuffixes = []string{"_one", "_few", "_many", "_other"}

//go:embed locales/*.json
var localeFS embed.FS

// catalogs maps a language code to its messages. Only languages with an
// embedded file are present.
var catalogs = mustLoadCatalogs()

func mustLoadCatalogs() map[string]map[string]string {
	out, err := loadCatalogs(localeFS)
	if err != nil {
		panic(err)
	}
	return out
}

func loadCatalogs(fsys fs.FS) (map[string]map[string]string, error) {
	entries, err := fs.ReadDir(fsys, "locales")
	if err != nil {
		return nil, fmt.Errorf("i18n: read embedded locales: %w", err)
	}
	out := make(map[string]map[string]string, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || path.Ext(name) != ".json" {
			continue
		}
		// "vi.json" or "<extension>.vi.json": the language is the last part.
		base := strings.TrimSuffix(name, ".json")
		lang := base[strings.LastIndex(base, ".")+1:]
		data, err := fs.ReadFile(fsys, "locales/"+name)
		if err != nil {
			return nil, fmt.Errorf("i18n: read %s: %w", name, err)
		}
		msgs := map[string]string{}
		if err := json.Unmarshal(data, &msgs); err != nil {
			return nil, fmt.Errorf("i18n: parse %s: %w", name, err)
		}
		dst, ok := out[lang]
		if !ok {
			dst = make(map[string]string, len(msgs))
			out[lang] = dst
		}
		for k, v := range msgs {
			if _, dup := dst[k]; dup {
				return nil, fmt.Errorf("i18n: %s: key %q is already defined for %s", name, k, lang)
			}
			dst[k] = v
		}
	}
	if _, ok := out[Default]; !ok {
		return nil, fmt.Errorf("i18n: missing %s.json", Default)
	}
	return out, nil
}

// Languages returns the codes that have an embedded catalog, sorted.
func Languages() []string {
	langs := make([]string, 0, len(catalogs))
	for l := range catalogs {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	return langs
}

// Catalog returns a copy of the embedded messages for lang, or nil.
func Catalog(lang string) map[string]string {
	src, ok := catalogs[lang]
	if !ok {
		return nil
	}
	cp := make(map[string]string, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

// IsSupported reports whether lang is one of the Supported codes.
func IsSupported(lang string) bool {
	for _, l := range Supported {
		if l == lang {
			return true
		}
	}
	return false
}

// Translator renders messages in one language.
type Translator struct {
	lang string
}

// New returns a translator for lang, or for Default when lang is not supported.
func New(lang string) *Translator {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if !IsSupported(lang) {
		lang = Default
	}
	return &Translator{lang: lang}
}

// FromRequest returns a translator for the language of the request.
func FromRequest(r *http.Request) *Translator {
	return New(ResolveLanguage(r))
}

// Lang returns the language code of the translator. A nil translator is
// English.
func (t *Translator) Lang() string {
	if t == nil {
		return Default
	}
	return t.lang
}

// T returns the message for key with its placeholders filled from args, given
// as name/value pairs: T("key", "count", 3, "err", err). Values are formatted
// with %v. A nil translator renders English.
func (t *Translator) T(key string, args ...interface{}) string {
	vals := argMap(args)
	count, hasCount := countArg(vals)

	langs := []string{t.Lang()}
	if langs[0] != Default {
		langs = append(langs, Default)
	}
	for _, lang := range langs {
		if msg, ok := lookup(lang, key, count, hasCount); ok {
			return fill(msg, vals)
		}
	}
	return key
}

func lookup(lang, key string, count int64, hasCount bool) (string, bool) {
	msgs := catalogs[lang]
	if msgs == nil {
		return "", false
	}
	if hasCount {
		if msg, ok := msgs[key+"_"+PluralCategory(lang, count)]; ok {
			return msg, true
		}
		if msg, ok := msgs[key+"_other"]; ok {
			return msg, true
		}
	}
	msg, ok := msgs[key]
	return msg, ok
}

func argMap(args []interface{}) map[string]string {
	if len(args) == 0 {
		return nil
	}
	vals := make(map[string]string, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		name, ok := args[i].(string)
		if !ok {
			name = fmt.Sprint(args[i])
		}
		vals[name] = fmt.Sprintf("%v", args[i+1])
	}
	return vals
}

func countArg(vals map[string]string) (int64, bool) {
	s, ok := vals["count"]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// fill replaces every {name} that has a value. Unknown placeholders are kept
// as written so a missing argument is visible instead of silently dropped.
func fill(msg string, vals map[string]string) string {
	if len(vals) == 0 || !strings.Contains(msg, "{") {
		return msg
	}
	var b strings.Builder
	for {
		open := strings.IndexByte(msg, '{')
		if open < 0 {
			break
		}
		end := strings.IndexByte(msg[open:], '}')
		if end < 0 {
			break
		}
		name := msg[open+1 : open+end]
		b.WriteString(msg[:open])
		if v, ok := vals[name]; ok && isPlaceholderName(name) {
			b.WriteString(v)
		} else {
			b.WriteString(msg[open : open+end+1])
		}
		msg = msg[open+end+1:]
	}
	b.WriteString(msg)
	return b.String()
}

func isPlaceholderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// Placeholders returns the sorted, de-duplicated placeholder names in msg.
func Placeholders(msg string) []string {
	seen := map[string]bool{}
	var names []string
	for {
		open := strings.IndexByte(msg, '{')
		if open < 0 {
			break
		}
		end := strings.IndexByte(msg[open:], '}')
		if end < 0 {
			break
		}
		name := msg[open+1 : open+end]
		if isPlaceholderName(name) && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		msg = msg[open+end+1:]
	}
	sort.Strings(names)
	return names
}

// PluralCategory returns the CLDR plural category ("one", "few", "many" or
// "other") of the integer n in lang.
func PluralCategory(lang string, n int64) string {
	if n < 0 {
		n = -n
	}
	switch lang {
	case "en":
		if n == 1 {
			return "one"
		}
		return "other"
	case "ru":
		mod10, mod100 := n%10, n%100
		switch {
		case mod10 == 1 && mod100 != 11:
			return "one"
		case mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14):
			return "few"
		default:
			return "many"
		}
	default:
		// vi, zh and ko have no plural forms.
		return "other"
	}
}

// ResolveLanguage picks the response language for r: the CookieName cookie
// when it holds a supported code, then Accept-Language, then Default.
func ResolveLanguage(r *http.Request) string {
	if r == nil {
		return Default
	}
	if c, err := r.Cookie(CookieName); err == nil {
		if lang := strings.ToLower(strings.TrimSpace(c.Value)); IsSupported(lang) {
			return lang
		}
	}
	if lang := MatchAcceptLanguage(r.Header.Get("Accept-Language")); lang != "" {
		return lang
	}
	return Default
}

// MatchAcceptLanguage returns the supported language the Accept-Language
// header value prefers most, or "" when none matches. Tags are matched on
// their primary subtag, so "zh-TW" and "zh-Hans-CN" both select "zh".
func MatchAcceptLanguage(header string) string {
	type candidate struct {
		lang string
		q    float64
	}
	var cands []candidate
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, params, _ := strings.Cut(part, ";")
		q := 1.0
		valid := true
		for _, p := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || v < 0 || v > 1 {
				valid = false
				break
			}
			q = v
		}
		if !valid || q == 0 {
			continue
		}
		tag = strings.ToLower(strings.TrimSpace(tag))
		primary, _, _ := strings.Cut(strings.ReplaceAll(tag, "_", "-"), "-")
		if !IsSupported(primary) {
			continue
		}
		cands = append(cands, candidate{lang: primary, q: q})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].q > cands[b].q })
	return cands[0].lang
}
