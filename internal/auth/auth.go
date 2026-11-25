package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "proxy_dash_session"
	SessionDuration   = 24 * time.Hour
)

var (
	ErrLockedOut        = errors.New("too many failed login attempts, please try again later")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrNoPasswordConfig = errors.New("dashboard password hash is not configured")
	ErrUnauthorized     = errors.New("unauthorized")
)

// LockoutError is returned by Login while a client is locked out. It matches
// ErrLockedOut with errors.Is and carries the remaining lockout time.
type LockoutError struct {
	Remaining time.Duration
}

func (e *LockoutError) Error() string {
	return fmt.Sprintf("%v (%d seconds remaining)", ErrLockedOut, e.RemainingSeconds())
}

// Unwrap lets errors.Is(err, ErrLockedOut) match.
func (e *LockoutError) Unwrap() error { return ErrLockedOut }

// RemainingSeconds returns the remaining lockout time in whole seconds,
// rounded up so a client is never told 0 seconds while still locked out.
func (e *LockoutError) RemainingSeconds() int {
	secs := int((e.Remaining + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// AuthManager handles authentication, session management, and rate limiting.
type AuthManager struct {
	passwordHash string
	sessionKey   []byte
	limiter      *RateLimiter
}

// NewAuthManager initializes AuthManager, loading or generating session signing key.
func NewAuthManager(dataDir, passwordHash string) (*AuthManager, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	keyPath := filepath.Join(dataDir, "session.key")
	sessionKey, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate session key: %w", err)
	}

	return &AuthManager{
		passwordHash: strings.TrimSpace(passwordHash),
		sessionKey:   sessionKey,
		limiter:      NewRateLimiter(5, 60*time.Second, 5*time.Minute),
	}, nil
}

func loadOrGenerateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) == 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to persist session key: %w", err)
	}
	return key, nil
}

// HashPassword hashes a raw password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Login authenticates password against configured bcrypt hash and issues a signed session cookie.
func (a *AuthManager) Login(password, clientIP string) (*http.Cookie, error) {
	if a.passwordHash == "" {
		return nil, ErrNoPasswordConfig
	}

	if locked, remaining := a.limiter.IsLockedOut(clientIP); locked {
		return nil, &LockoutError{Remaining: remaining}
	}

	err := bcrypt.CompareHashAndPassword([]byte(a.passwordHash), []byte(password))
	if err != nil {
		a.limiter.RecordFailure(clientIP)
		return nil, ErrInvalidPassword
	}

	// Reset failed attempts on success
	a.limiter.Reset(clientIP)

	// Issue signed session cookie
	return a.CreateSessionCookie(), nil
}

// CreateSessionCookie generates a signed session cookie.
func (a *AuthManager) CreateSessionCookie() *http.Cookie {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%d:%s", timestamp, hex.EncodeToString(nonce))
	sig := a.sign(payload)
	val := fmt.Sprintf("%s.%s", payload, sig)

	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    val,
		Path:     "/",
		Expires:  time.Now().Add(SessionDuration),
		MaxAge:   int(SessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// ClearSessionCookie creates an expired cookie to clear session.
func (a *AuthManager) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// VerifyRequest validates the session cookie from incoming HTTP request.
func (a *AuthManager) VerifyRequest(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return a.VerifyToken(cookie.Value)
}

// VerifyToken validates the payload and HMAC-SHA256 signature.
func (a *AuthManager) VerifyToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	payload := parts[0]
	signature := parts[1]

	expectedSig := a.sign(payload)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return false
	}

	// Validate timestamp inside payload
	payloadParts := strings.Split(payload, ":")
	if len(payloadParts) < 2 {
		return false
	}

	ts, err := strconv.ParseInt(payloadParts[0], 10, 64)
	if err != nil {
		return false
	}

	issuedAt := time.Unix(ts, 0)
	if time.Since(issuedAt) > SessionDuration || issuedAt.After(time.Now().Add(5*time.Minute)) {
		return false
	}

	return true
}

func (a *AuthManager) sign(payload string) string {
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// GetClientIP returns the address of the TCP peer. The dashboard is served
// directly, with no trusted reverse proxy in front, so X-Forwarded-For and
// X-Real-IP are attacker-controlled and must not feed the login rate limiter.
func GetClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
