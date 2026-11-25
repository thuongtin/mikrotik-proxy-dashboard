package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/i18n"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
)

// callLang is call with optional language cookie and Accept-Language header.
func callLang(t *testing.T, srv *Server, session *http.Cookie, langCookie, acceptLang, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if session != nil {
		req.AddCookie(session)
	}
	if langCookie != "" {
		req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: langCookie})
	}
	if acceptLang != "" {
		req.Header.Set("Accept-Language", acceptLang)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", w.Body.String(), err)
	}
	return body.Error
}

func TestAPIErrorsAreLocalized(t *testing.T) {
	srv, _, session := newHardeningServer(t)

	cases := []struct {
		name       string
		langCookie string
		acceptLang string
		want       string
	}{
		{"default is English", "", "", "Proxy not found"},
		{"cookie vi", "vi", "", "Proxy không tồn tại"},
		{"Accept-Language vi", "", "vi-VN,vi;q=0.9,en;q=0.5", "Proxy không tồn tại"},
		{"cookie wins over header", "en", "vi", "Proxy not found"},
		{"unsupported cookie falls back to header", "xx", "vi", "Proxy không tồn tại"},
		{"unsupported header falls back to English", "", "fr-FR,de;q=0.8", "Proxy not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := callLang(t, srv, session, tc.langCookie, tc.acceptLang, http.MethodGet, "/api/proxies/missing", nil)
			if w.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d (%s)", w.Code, w.Body.String())
			}
			if got := errorMessage(t, w); got != tc.want {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
			vary := strings.Join(w.Header().Values("Vary"), ", ")
			if !strings.Contains(vary, "Cookie") || !strings.Contains(vary, "Accept-Language") {
				t.Fatalf("Vary = %q, want Cookie and Accept-Language", vary)
			}
		})
	}
}

func TestLoginErrorsAreLocalized(t *testing.T) {
	srv, _, _ := newHardeningServer(t)
	body := []byte(`{"password":"wrong"}`)

	w := callLang(t, srv, nil, "", "", http.MethodPost, "/api/auth/login", body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (%s)", w.Code, w.Body.String())
	}
	if got := errorMessage(t, w); got != "Invalid password" {
		t.Fatalf("English login error = %q", got)
	}

	w = callLang(t, srv, nil, "vi", "", http.MethodPost, "/api/auth/login", body)
	if got := errorMessage(t, w); got != "Mật khẩu không đúng" {
		t.Fatalf("Vietnamese login error = %q", got)
	}
}

func TestProxyInUsePluralIsLocalized(t *testing.T) {
	srv, _, session := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, testDeviceMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}

	w := callLang(t, srv, session, "", "", http.MethodDelete, "/api/proxies/p1", nil)
	if got := errorMessage(t, w); !strings.HasPrefix(got, "The proxy is assigned to 1 device: ") || !strings.Contains(got, "Laptop") {
		t.Fatalf("English in-use error = %q", got)
	}

	w = callLang(t, srv, session, "vi", "", http.MethodDelete, "/api/proxies/p1", nil)
	if got := errorMessage(t, w); !strings.HasPrefix(got, "Proxy đang được gán cho 1 thiết bị: ") {
		t.Fatalf("Vietnamese in-use error = %q", got)
	}
}
