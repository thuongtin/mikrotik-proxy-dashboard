package mikrotik

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a REST API client for MikroTik RouterOS v7.
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient initializes a MikroTik REST client.
func NewClient(rawURL, username, password string, insecureTLS bool) (*Client, error) {
	baseURL := strings.TrimRight(rawURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureTLS,
		},
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

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mikrotik API error (status %d): %s", resp.StatusCode, string(respData))
	}

	if out != nil && len(respData) > 0 {
		if err := json.Unmarshal(respData, out); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w (raw: %s)", err, string(respData))
		}
	}

	return nil
}

// BuildQueryParam constructs RouterOS REST filter queries.
func BuildQueryParam(key, val string) string {
	return fmt.Sprintf("?%s=%s", url.QueryEscape(key), url.QueryEscape(val))
}
