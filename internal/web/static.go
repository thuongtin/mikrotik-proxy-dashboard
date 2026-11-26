package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// indexPage is index.html as served: the embedded file with the stylesheet
// and script of every frontend extension under ext/ linked in. An edition
// without extensions ships no ext/ directory and serves the file unchanged.
type indexPage struct {
	body []byte
	etag string
}

// buildIndex reads index.html and links ext/*.css before </head> and
// ext/*.js before </body>. Extension scripts are deferred, so they run after
// app.js and register before the page boots.
func buildIndex(fsys fs.FS) (*indexPage, error) {
	body, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return nil, err
	}
	css, err := fs.Glob(fsys, "ext/*.css")
	if err != nil {
		return nil, err
	}
	js, err := fs.Glob(fsys, "ext/*.js")
	if err != nil {
		return nil, err
	}
	var links, scripts strings.Builder
	for _, p := range css {
		links.WriteString(`  <link rel="stylesheet" href="` + html.EscapeString(p) + `">` + "\n")
	}
	for _, p := range js {
		scripts.WriteString(`  <script src="` + html.EscapeString(p) + `" defer></script>` + "\n")
	}
	body = insertBefore(body, "</head>", links.String())
	body = insertBefore(body, "</body>", scripts.String())
	sum := sha256.Sum256(body)
	return &indexPage{body: body, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}, nil
}

// insertBefore puts text right before the last occurrence of tag, or at the
// end when the tag is missing.
func insertBefore(body []byte, tag, text string) []byte {
	if text == "" {
		return body
	}
	i := bytes.LastIndex(body, []byte(tag))
	if i < 0 {
		i = len(body)
	}
	out := make([]byte, 0, len(body)+len(text))
	out = append(out, body[:i]...)
	out = append(out, text...)
	return append(out, body[i:]...)
}

// serveIndex answers with the built index page. It returns false when there
// is none, so the caller serves the embedded file as is.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) bool {
	if s.index == nil {
		return false
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", s.index.etag)
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(s.index.body))
	return true
}
