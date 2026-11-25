package mikrotik

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// maxResponseBytes caps how much of a RouterOS response is read. A large
	// connection table is a few megabytes; anything beyond this is refused.
	maxResponseBytes = 32 << 20
	// maxErrorBodyChars caps how much of a response body is echoed in errors.
	maxErrorBodyChars = 300
)

// Options controls how the client verifies the RouterOS TLS certificate.
type Options struct {
	// InsecureTLS disables certificate verification. Only for lab use: anyone
	// on the path can then read the router credentials.
	InsecureTLS bool
	// CAFile is a PEM file with the certificate (or its CA) that RouterOS
	// presents on www-ssl. When empty the system trust store is used.
	CAFile string
}

// APIError is a non-2xx answer from the RouterOS REST API.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mikrotik API error on %s %s (status %d): %s", e.Method, e.Path, e.Status, e.Body)
}

// IsNotFound reports whether err is a RouterOS "no such item" answer.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// Client is a REST API client for MikroTik RouterOS v7.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient initializes a MikroTik REST client.
func NewClient(rawURL, username, password string, opts Options) (*Client, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureTLS, // #nosec G402 -- explicit opt-in via MIKROTIK_INSECURE_TLS
	}

	if opts.CAFile != "" {
		pemData, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read MikroTik CA file %s: %w", opts.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("MikroTik CA file %s contains no PEM certificate", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	return &Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
		},
	}, nil
}

// Do executes a REST request against RouterOS.
func (c *Client) Do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	reqURL := fmt.Sprintf("%s/rest%s", c.baseURL, path)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mikrotik request %s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("failed to read response of %s %s: %w", method, path, err)
	}
	if len(respData) > maxResponseBytes {
		return fmt.Errorf("mikrotik response of %s %s exceeds %d bytes", method, path, maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: truncateBody(respData)}
	}

	if out != nil && len(bytes.TrimSpace(respData)) > 0 {
		if err := json.Unmarshal(respData, out); err != nil {
			return fmt.Errorf("failed to decode response of %s %s: %w", method, path, err)
		}
	}

	return nil
}

// truncateBody keeps error messages short and free of control characters.
func truncateBody(data []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(string(data), "?"))
	s = strings.TrimSpace(s)
	if runes := []rune(s); len(runes) > maxErrorBodyChars {
		s = string(runes[:maxErrorBodyChars]) + "..."
	}
	return s
}

// BuildQueryParam constructs RouterOS REST filter queries.
func BuildQueryParam(key, val string) string {
	return fmt.Sprintf("?%s=%s", url.QueryEscape(key), url.QueryEscape(val))
}
