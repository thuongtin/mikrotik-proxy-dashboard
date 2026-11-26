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
	// SessionIdleTimeout ends a session that has not been used for this long.
	SessionIdleTimeout = 7 * 24 * time.Hour
	// SessionMaxLifetime ends every session this long after sign-in, used or not.
	SessionMaxLifetime = 30 * 24 * time.Hour
	// sessionRenewAfter is how old a token gets before a request replaces it
	// with a fresh one, which keeps a session in use from timing out.
	sessionRenewAfter = time.Hour
	// sessionClockSkew is how far in the future a token may claim to be issued.
	sessionClockSkew = 5 * time.Minute
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
	now          func() time.Time
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
		now:          time.Now,
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

// CreateSessionCookie generates a signed session cookie for a new sign-in.
func (a *AuthManager) CreateSessionCookie() *http.Cookie {
	now := a.now()
	return a.sessionCookie(now, now)
}

// sessionCookie signs a token issued at now for a session that signed in at
// loginAt. The payload is "issued:login:nonce". The cookie lives until the
// idle timeout or the end of the session's lifetime, whichever comes first.
func (a *AuthManager) sessionCookie(loginAt, now time.Time) *http.Cookie {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	payload := fmt.Sprintf("%d:%d:%s", now.Unix(), loginAt.Unix(), hex.EncodeToString(nonce))
	val := fmt.Sprintf("%s.%s", payload, a.sign(payload))

	expires := now.Add(SessionIdleTimeout)
	if end := loginAt.Add(SessionMaxLifetime); end.Before(expires) {
		expires = end
	}
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    val,
		Path:     "/",
		Expires:  expires,
		MaxAge:   max(int(expires.Sub(now).Seconds()), 1),
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
	ok, _ := a.Authenticate(r)
	return ok
}

// Authenticate validates the session cookie of a request. For a valid token
// older than sessionRenewAfter it also returns a fresh cookie for the same
// session, so a dashboard in use stays signed in until SessionMaxLifetime.
// renewed is nil when the token is invalid or still fresh.
func (a *AuthManager) Authenticate(r *http.Request) (ok bool, renewed *http.Cookie) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return false, nil
	}
	now := a.now()
	issuedAt, loginAt, ok := a.parseToken(cookie.Value, now)
	if !ok {
		return false, nil
	}
	if now.Sub(issuedAt) >= sessionRenewAfter {
		renewed = a.sessionCookie(loginAt, now)
	}
	return true, renewed
}

// VerifyToken validates the payload and HMAC-SHA256 signature.
func (a *AuthManager) VerifyToken(token string) bool {
	_, _, ok := a.parseToken(token, a.now())
	return ok
}

// parseToken checks the signature and the age of a token and returns when it
// was issued and when its session signed in. Tokens from before session
// renewal carry "issued:nonce"; their sign-in time is their issue time.
func (a *AuthManager) parseToken(token string, now time.Time) (issuedAt, loginAt time.Time, ok bool) {
	payload, signature, found := strings.Cut(token, ".")
	if !found || strings.Contains(signature, ".") {
		return time.Time{}, time.Time{}, false
	}
	if subtle.ConstantTimeCompare([]byte(signature), []byte(a.sign(payload))) != 1 {
		return time.Time{}, time.Time{}, false
	}

	parts := strings.Split(payload, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return time.Time{}, time.Time{}, false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	login := issued
	if len(parts) == 3 {
		if login, err = strconv.ParseInt(parts[1], 10, 64); err != nil {
			return time.Time{}, time.Time{}, false
		}
	}
	issuedAt, loginAt = time.Unix(issued, 0), time.Unix(login, 0)

	switch {
	case issuedAt.After(now.Add(sessionClockSkew)), loginAt.After(issuedAt):
		return time.Time{}, time.Time{}, false
	case now.Sub(issuedAt) > SessionIdleTimeout, now.Sub(loginAt) > SessionMaxLifetime:
		return time.Time{}, time.Time{}, false
	}
	return issuedAt, loginAt, true
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
