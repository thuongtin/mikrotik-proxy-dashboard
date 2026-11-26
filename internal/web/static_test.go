package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/auth"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

func TestStaticFilesRevalidate(t *testing.T) {
	dir := t.TempDir()
	hash, err := auth.HashPassword("AdminPass123!")
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewAuthManager(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"index.html": {Data: []byte("<html>index</html>")},
		"app.js":     {Data: []byte("console.log(1)")},
	}
	srv := NewServer(&config.Config{DataDir: dir}, authMgr, st, singbox.NewSupervisor("sing-box", dir), nil, files)

	get := func(path, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	w := get("/app.js", "")
	tag := w.Header().Get("ETag")
	if w.Code != http.StatusOK || tag == "" || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("app.js: %d etag=%q cache=%q", w.Code, tag, w.Header().Get("Cache-Control"))
	}
	if w := get("/app.js", tag); w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", w.Code)
	}

	// A client-side route falls back to index.html and must carry its tag,
	// not the tag of the path that was asked for.
	idx := get("/", "").Header().Get("ETag")
	if w := get("/devices", ""); w.Code != http.StatusOK || w.Header().Get("ETag") != idx || idx == tag {
		t.Fatalf("fallback: %d etag=%q index=%q", w.Code, w.Header().Get("ETag"), idx)
	}
}

func TestIndexLinksExtensions(t *testing.T) {
	page := "<html><head>\n</head><body>\n  <script src=\"app.js\" defer></script>\n</body></html>"
	plain, err := buildIndex(fstest.MapFS{"index.html": {Data: []byte(page)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain.body) != page {
		t.Fatalf("index without extensions changed:\n%s", plain.body)
	}

	ext, err := buildIndex(fstest.MapFS{
		"index.html":   {Data: []byte(page)},
		"ext/b.js":     {Data: []byte("1")},
		"ext/a.js":     {Data: []byte("2")},
		"ext/a.css":    {Data: []byte("x{}")},
		"ext/notes.md": {Data: []byte("not linked")},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := string(ext.body)
	css := strings.Index(body, `<link rel="stylesheet" href="ext/a.css">`)
	app := strings.Index(body, `src="app.js"`)
	a := strings.Index(body, `<script src="ext/a.js" defer></script>`)
	b := strings.Index(body, `<script src="ext/b.js" defer></script>`)
	if css < 0 || css > strings.Index(body, "</head>") || a < app || b < a || b > strings.Index(body, "</body>") {
		t.Fatalf("extensions not linked in order:\n%s", body)
	}
	if strings.Contains(body, "notes.md") {
		t.Fatalf("non-asset file linked:\n%s", body)
	}
	if ext.etag == plain.etag {
		t.Fatal("ETag does not follow the served bytes")
	}
}

func TestIndexServedWithExtensions(t *testing.T) {
	dir := t.TempDir()
	hash, err := auth.HashPassword("AdminPass123!")
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewAuthManager(dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"index.html": {Data: []byte("<html><head></head><body></body></html>")},
		"ext/x.js":   {Data: []byte("1")},
	}
	srv := NewServer(&config.Config{DataDir: dir}, authMgr, st, singbox.NewSupervisor("sing-box", dir), nil, files)

	get := func(path, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	root := get("/", "")
	tag := root.Header().Get("ETag")
	if root.Code != http.StatusOK || tag == "" || !strings.Contains(root.Body.String(), `src="ext/x.js"`) {
		t.Fatalf("index: %d etag=%q body=%q", root.Code, tag, root.Body.String())
	}
	if ct := root.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("index content type %q", ct)
	}
	for _, path := range []string{"/index.html", "/devices"} {
		w := get(path, "")
		if w.Code != http.StatusOK || w.Header().Get("ETag") != tag || w.Body.String() != root.Body.String() {
			t.Fatalf("%s: %d etag=%q", path, w.Code, w.Header().Get("ETag"))
		}
	}
	if w := get("/devices", tag); w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", w.Code)
	}
	if w := get("/ext/x.js", ""); w.Code != http.StatusOK || w.Body.String() != "1" {
		t.Fatalf("extension script: %d %q", w.Code, w.Body.String())
	}
}
