package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAuthManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "auth_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	password := "SecretPass123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mgr, err := NewAuthManager(tempDir, hash)
	if err != nil {
		t.Fatalf("failed to create AuthManager: %v", err)
	}

	clientIP := "192.168.1.100"

	// Test 1: Invalid password
	_, err = mgr.Login("wrong_password", clientIP)
	if err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got: %v", err)
	}

	// Test 2: Rate limiting (5 attempts)
	for i := 0; i < 4; i++ {
		_, _ = mgr.Login("wrong_password", clientIP)
	}
	// 6th attempt should be locked out
	_, err = mgr.Login(password, clientIP)
	if err == nil || !mgr.limiter.RecordFailure(clientIP) {
		locked, _ := mgr.limiter.IsLockedOut(clientIP)
		if !locked {
			t.Fatalf("expected client IP to be locked out after 5 failures")
		}
	}

	// Test 3: Reset and successful login
	mgr.limiter.Reset(clientIP)
	cookie, err := mgr.Login(password, clientIP)
	if err != nil {
		t.Fatalf("expected successful login, got: %v", err)
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("expected valid session cookie")
	}

	// Test 4: Verify valid cookie
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.AddCookie(cookie)
	if !mgr.VerifyRequest(req) {
		t.Fatalf("expected cookie to be valid")
	}

	// Test 5: Verify tampered cookie
	tamperedCookie := &http.Cookie{
		Name:  SessionCookieName,
		Value: cookie.Value + "tampered",
	}
	reqTampered := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	reqTampered.AddCookie(tamperedCookie)
	if mgr.VerifyRequest(reqTampered) {
		t.Fatalf("expected tampered cookie to be rejected")
	}
}

func TestRateLimiterLockoutExpiry(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond, 100*time.Millisecond)
	ip := "10.0.0.1"

	rl.RecordFailure(ip)
	locked, _ := rl.IsLockedOut(ip)
	if locked {
		t.Fatalf("should not be locked out on 1st failure")
	}

	rl.RecordFailure(ip)
	locked, _ = rl.IsLockedOut(ip)
	if !locked {
		t.Fatalf("should be locked out on 2nd failure")
	}

	time.Sleep(120 * time.Millisecond)
	locked, _ = rl.IsLockedOut(ip)
	if locked {
		t.Fatalf("lockout should have expired")
	}
}

func TestGetClientIPIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "10.88.88.77:51234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("X-Real-IP", "9.9.9.9")

	if got := GetClientIP(req); got != "10.88.88.77" {
		t.Fatalf("expected TCP peer 10.88.88.77, got %q", got)
	}

	req.RemoteAddr = "[fd00::1234]:443"
	if got := GetClientIP(req); got != "fd00::1234" {
		t.Fatalf("expected IPv6 peer fd00::1234, got %q", got)
	}
}

func TestRateLimitCannotBeBypassedWithSpoofedHeaders(t *testing.T) {
	tempDir := t.TempDir()
	hash, err := HashPassword("SecretPass123!")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	mgr, err := NewAuthManager(tempDir, hash)
	if err != nil {
		t.Fatalf("failed to create AuthManager: %v", err)
	}

	// Every attempt claims a different forwarded address; all of them must be
	// counted against the one real peer.
	lockedOut := false
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = "10.88.88.77:40000"
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('0'+i%10)))
		if _, err := mgr.Login("wrong-password", GetClientIP(req)); err == nil {
			t.Fatalf("login with a wrong password must fail")
		}
		if locked, _ := mgr.limiter.IsLockedOut("10.88.88.77"); locked {
			lockedOut = true
			break
		}
	}
	if !lockedOut {
		t.Fatalf("expected the real peer to be locked out despite spoofed headers")
	}
}

// sessionClock lets a test move the AuthManager's clock.
type sessionClock struct{ t time.Time }

func (c *sessionClock) now() time.Time          { return c.t }
func (c *sessionClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newSessionTestManager(t *testing.T) (*AuthManager, *sessionClock) {
	t.Helper()
	mgr, err := NewAuthManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("failed to create AuthManager: %v", err)
	}
	clock := &sessionClock{t: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}
	mgr.now = clock.now
	return mgr, clock
}

func requestWith(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	req.AddCookie(c)
	return req
}

func TestSessionRenewsWhileInUse(t *testing.T) {
	mgr, clock := newSessionTestManager(t)
	cookie := mgr.CreateSessionCookie()
	if cookie.MaxAge != int(SessionIdleTimeout.Seconds()) {
		t.Fatalf("new cookie MaxAge = %d, want the idle timeout", cookie.MaxAge)
	}

	// A fresh token is accepted without a new cookie.
	clock.advance(10 * time.Minute)
	ok, renewed := mgr.Authenticate(requestWith(cookie))
	if !ok || renewed != nil {
		t.Fatalf("fresh token: ok=%v renewed=%v, want ok and no renewal", ok, renewed != nil)
	}

	// Used every day for three weeks, the session stays signed in: each
	// request past sessionRenewAfter hands out a replacement.
	for day := 0; day < 21; day++ {
		clock.advance(24 * time.Hour)
		ok, renewed := mgr.Authenticate(requestWith(cookie))
		if !ok {
			t.Fatalf("day %d: session in use was rejected", day+1)
		}
		if renewed == nil {
			t.Fatalf("day %d: expected a renewed cookie", day+1)
		}
		cookie = renewed
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	mgr, clock := newSessionTestManager(t)
	cookie := mgr.CreateSessionCookie()

	clock.advance(SessionIdleTimeout - time.Minute)
	if !mgr.VerifyRequest(requestWith(cookie)) {
		t.Fatalf("token just inside the idle timeout must be valid")
	}
	clock.advance(2 * time.Minute)
	if mgr.VerifyRequest(requestWith(cookie)) {
		t.Fatalf("token unused past the idle timeout must be rejected")
	}
}

func TestSessionMaxLifetime(t *testing.T) {
	mgr, clock := newSessionTestManager(t)
	cookie := mgr.CreateSessionCookie()

	for elapsed := time.Duration(0); elapsed < SessionMaxLifetime-48*time.Hour; elapsed += 48 * time.Hour {
		clock.advance(48 * time.Hour)
		ok, renewed := mgr.Authenticate(requestWith(cookie))
		if !ok || renewed == nil {
			t.Fatalf("after %v: ok=%v renewed=%v", elapsed+48*time.Hour, ok, renewed != nil)
		}
		cookie = renewed
	}

	// A renewed cookie never outlives the session's lifetime.
	end := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC).Add(SessionMaxLifetime)
	if cookie.Expires.After(end) {
		t.Fatalf("renewed cookie expires %v, after the session end %v", cookie.Expires, end)
	}

	clock.t = end.Add(time.Minute)
	if mgr.VerifyRequest(requestWith(cookie)) {
		t.Fatalf("session past its max lifetime must be rejected even when in use")
	}
}

func TestSessionAcceptsLegacyToken(t *testing.T) {
	mgr, clock := newSessionTestManager(t)

	// Tokens issued before renewal carry "issued:nonce".
	payload := fmt.Sprintf("%d:%s", clock.t.Unix(), "00112233445566778899aabbccddeeff")
	legacy := &http.Cookie{Name: SessionCookieName, Value: payload + "." + mgr.sign(payload)}

	clock.advance(2 * time.Hour)
	ok, renewed := mgr.Authenticate(requestWith(legacy))
	if !ok || renewed == nil {
		t.Fatalf("legacy token: ok=%v renewed=%v, want ok and a renewal", ok, renewed != nil)
	}
	if !mgr.VerifyRequest(requestWith(renewed)) {
		t.Fatalf("cookie renewed from a legacy token must be valid")
	}
}

func TestSessionRejectsBadTokens(t *testing.T) {
	mgr, clock := newSessionTestManager(t)
	signed := func(payload string) string { return payload + "." + mgr.sign(payload) }
	now := clock.t.Unix()

	cases := map[string]string{
		"future issue time":    signed(fmt.Sprintf("%d:%d:ab", now+3600, now)),
		"login after issue":    signed(fmt.Sprintf("%d:%d:ab", now, now+60)),
		"too many fields":      signed(fmt.Sprintf("%d:%d:ab:cd", now, now)),
		"non-numeric login":    signed(fmt.Sprintf("%d:x:ab", now)),
		"extra signature part": signed(fmt.Sprintf("%d:%d:ab", now, now)) + ".00",
		"no signature":         fmt.Sprintf("%d:%d:ab", now, now),
	}
	for name, value := range cases {
		if mgr.VerifyToken(value) {
			t.Errorf("%s: token accepted", name)
		}
	}
}
