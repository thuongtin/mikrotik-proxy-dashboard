package auth

import (
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
