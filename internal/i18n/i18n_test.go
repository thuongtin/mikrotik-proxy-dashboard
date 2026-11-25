package i18n

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func request(cookie, accept string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: cookie})
	}
	if accept != "" {
		r.Header.Set("Accept-Language", accept)
	}
	return r
}

func TestResolveLanguageOrder(t *testing.T) {
	cases := []struct {
		name, cookie, accept, want string
	}{
		{"nothing", "", "", "en"},
		{"cookie only", "vi", "", "vi"},
		{"cookie is case-insensitive", " KO ", "", "ko"},
		{"cookie beats header", "ru", "vi", "ru"},
		{"unsupported cookie uses header", "fr", "zh-CN", "zh"},
		{"header only", "", "ko-KR,ko;q=0.9", "ko"},
		{"unsupported header uses default", "", "fr,de;q=0.5", "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveLanguage(request(tc.cookie, tc.accept)); got != tc.want {
				t.Fatalf("ResolveLanguage = %q, want %q", got, tc.want)
			}
		})
	}
	if got := ResolveLanguage(nil); got != Default {
		t.Fatalf("nil request = %q, want %q", got, Default)
	}
	if got := FromRequest(request("vi", "")).Lang(); got != "vi" {
		t.Fatalf("FromRequest lang = %q", got)
	}
}

func TestMatchAcceptLanguage(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"vi":                          "vi",
		"zh-TW":                       "zh",
		"zh-Hans-CN,en;q=0.8":         "zh",
		"zh_CN":                       "zh",
		"RU-ru":                       "ru",
		"fr-FR,ru;q=0.4,ko;q=0.7":     "ko",
		"en;q=0.2, vi;q=0.9":          "vi",
		"vi;q=0, en;q=0.1":            "en",
		"vi;q=abc, ko":                "ko",
		"vi;q=2":                      "",
		"*":                           "",
		"de, fr;q=0.9":                "",
		"en-US,en;q=0.9,vi;q=0.9":     "en",
		"ko;q=0.5, ru;q=0.5":          "ko",
		"  vi  ;  q = 0.8 , en;q=0.7": "vi",
	}
	for header, want := range cases {
		if got := MatchAcceptLanguage(header); got != want {
			t.Errorf("MatchAcceptLanguage(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestPlaceholderFill(t *testing.T) {
	tr := New("en")
	err := errors.New("connection refused")
	if got, want := tr.T("api.proxy.invalid", "err", err), "Invalid proxy: connection refused"; got != want {
		t.Fatalf("T = %q, want %q", got, want)
	}
	if got, want := tr.T("api.system.reconcile_both_failed", "router", "r-err", "singbox", "s-err"),
		"Sync failed on both sides. Router: r-err. sing-box: s-err"; got != want {
		t.Fatalf("T = %q, want %q", got, want)
	}
	// A missing argument stays visible instead of disappearing.
	if got := tr.T("api.proxy.invalid"); got != "Invalid proxy: {err}" {
		t.Fatalf("missing arg = %q", got)
	}
	// Values are inserted as is, braces in values are not expanded again.
	if got := tr.T("api.proxy.invalid", "err", "{count}", "count", 3); got != "Invalid proxy: {count}" {
		t.Fatalf("value with braces = %q", got)
	}
	if got := fill("a {x} b {y} {not valid} {", map[string]string{"x": "1", "y": "2"}); got != "a 1 b 2 {not valid} {" {
		t.Fatalf("fill = %q", got)
	}
	if got := Placeholders("{b} {a} {b} {no space}"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("Placeholders = %v", got)
	}
}

func TestFallbacks(t *testing.T) {
	if got := New("xx").Lang(); got != Default {
		t.Fatalf("unsupported language = %q", got)
	}
	var nilTr *Translator
	if got := nilTr.T("api.not_found"); got != "Endpoint not found" {
		t.Fatalf("nil translator = %q", got)
	}
	if got := New("vi").T("no.such.key"); got != "no.such.key" {
		t.Fatalf("unknown key = %q", got)
	}
	if got := New("vi").T("api.not_found"); got != "Endpoint không tồn tại" {
		t.Fatalf("vi = %q", got)
	}
	// vi has only _other for counted keys.
	if got := New("vi").T("leak.l1.ok", "count", 1); got != "1 thiết bị được cố định IP tĩnh (Static Lease)" {
		t.Fatalf("vi plural = %q", got)
	}
	// Catalogs for zh, ru and ko may be missing or partial: English fills in.
	for _, lang := range []string{"zh", "ru", "ko"} {
		if _, ok := catalogs[lang]["api.not_found"]; ok {
			continue
		}
		if got := New(lang).T("api.not_found"); got != "Endpoint not found" {
			t.Fatalf("%s fallback = %q", lang, got)
		}
	}
}

func TestPluralCategory(t *testing.T) {
	en := map[int64]string{0: "other", 1: "one", 2: "other", 11: "other", 21: "other", -1: "one"}
	for n, want := range en {
		if got := PluralCategory("en", n); got != want {
			t.Errorf("en %d = %q, want %q", n, got, want)
		}
	}
	ru := map[int64]string{
		0: "many", 1: "one", 2: "few", 4: "few", 5: "many", 11: "many", 12: "many",
		14: "many", 21: "one", 22: "few", 25: "many", 101: "one", 111: "many", 112: "many", 1004: "few",
	}
	for n, want := range ru {
		if got := PluralCategory("ru", n); got != want {
			t.Errorf("ru %d = %q, want %q", n, got, want)
		}
	}
	for _, lang := range []string{"vi", "zh", "ko"} {
		for _, n := range []int64{0, 1, 2, 5} {
			if got := PluralCategory(lang, n); got != "other" {
				t.Errorf("%s %d = %q, want other", lang, n, got)
			}
		}
	}
}

func TestPluralSelectionEnglish(t *testing.T) {
	tr := New("en")
	if got, want := tr.T("leak.l1.ok", "count", 1), "1 device has its IP pinned (static lease)"; got != want {
		t.Fatalf("one = %q, want %q", got, want)
	}
	if got, want := tr.T("leak.l1.ok", "count", 3), "3 devices have their IP pinned (static lease)"; got != want {
		t.Fatalf("other = %q, want %q", got, want)
	}
	if got, want := tr.T("leak.l1.ok", "count", int64(0)), "0 devices have their IP pinned (static lease)"; got != want {
		t.Fatalf("zero = %q, want %q", got, want)
	}
}

func TestPluralSelectionRussian(t *testing.T) {
	// The ru catalog may not exist yet, so test lookup against a temporary one.
	saved, had := catalogs["ru"]
	catalogs["ru"] = map[string]string{
		"t.files_one":   "{count} файл",
		"t.files_few":   "{count} файла",
		"t.files_many":  "{count} файлов",
		"t.files_other": "{count} файла (other)",
		"t.only_other":  "x",
	}
	catalogs["ru"]["t.only_other_other"] = "{count} other"
	defer func() {
		if had {
			catalogs["ru"] = saved
		} else {
			delete(catalogs, "ru")
		}
	}()

	tr := New("ru")
	cases := map[int]string{1: "1 файл", 2: "2 файла", 5: "5 файлов", 11: "11 файлов", 21: "21 файл", 23: "23 файла"}
	for n, want := range cases {
		if got := tr.T("t.files", "count", n); got != want {
			t.Errorf("ru %d = %q, want %q", n, got, want)
		}
	}
	// Missing category falls back to _other before the bare key.
	if got := tr.T("t.only_other", "count", 1); got != "1 other" {
		t.Errorf("fallback to _other = %q", got)
	}
	// Without a count the bare key is used.
	if got := tr.T("t.only_other"); got != "x" {
		t.Errorf("bare key = %q", got)
	}
}

func baseKey(k string) string {
	for _, s := range PluralSuffixes {
		if strings.HasSuffix(k, s) {
			return strings.TrimSuffix(k, s)
		}
	}
	return k
}

// TestCatalogConsistency checks every embedded locale against en: no extra
// keys, and the same placeholders. Plural variants are compared with en
// _other. Missing keys are allowed (English is used) and only logged.
func TestCatalogConsistency(t *testing.T) {
	en := Catalog(Default)
	if len(en) == 0 {
		t.Fatal("en catalog is empty")
	}
	enBase := map[string]string{}
	for k, v := range en {
		b := baseKey(k)
		if b != k && !strings.HasSuffix(k, "_other") {
			continue
		}
		enBase[b] = v
	}
	for k := range en {
		if b := baseKey(k); b != k {
			if _, ok := en[b+"_other"]; !ok {
				t.Errorf("en: plural key %q has no %s_other", k, b)
			}
		}
	}
	for k, v := range en {
		if strings.ContainsRune(v, '\u2014') {
			t.Errorf("en: %q contains an em dash", k)
		}
	}

	for _, lang := range Languages() {
		if !IsSupported(lang) {
			t.Errorf("embedded catalog %q is not in Supported", lang)
		}
		if lang == Default {
			continue
		}
		msgs := Catalog(lang)
		for k, v := range msgs {
			if strings.ContainsRune(v, '\u2014') {
				t.Errorf("%s: %q contains an em dash", lang, k)
			}
			// Plural variants and bare keys are both checked against the en
			// message (en _other for counted keys).
			ref, ok := enBase[baseKey(k)]
			if !ok {
				t.Errorf("%s: key %q does not exist in en", lang, k)
				continue
			}
			if got, want := Placeholders(v), Placeholders(ref); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: %q placeholders %v, en has %v", lang, k, got, want)
			}
		}
		missing := 0
		for b := range enBase {
			if _, ok := msgs[b]; ok {
				continue
			}
			found := false
			for _, s := range PluralSuffixes {
				if _, ok := msgs[b+s]; ok {
					found = true
					break
				}
			}
			if !found {
				missing++
			}
		}
		t.Logf("%s: %d keys, %d of %d messages missing (English is used)", lang, len(msgs), missing, len(enBase))
	}
}
