package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	sensitiveRegex = regexp.MustCompile(`(?i)(password|pass|secret|uuid|token|pbk|sid)[=:\s"]+([^\s,"]+)`)
)

func sanitizeError(errStr string) string {
	return sensitiveRegex.ReplaceAllString(errStr, "$1=***")
}

type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Query       string `json:"query"`
}

type ipifyResponse struct {
	IP string `json:"ip"`
}

// TestOptions configures ephemeral proxy testing environment.
type TestOptions struct {
	SingboxPath string
	VethIF      string
	ContainerGW string
}

// BoundedBuffer thread-safely captures output up to a maximum size.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() >= b.max {
		return len(p), nil
	}
	remaining := b.max - b.buf.Len()
	if len(p) > remaining {
		b.buf.Write(p[:remaining])
	} else {
		b.buf.Write(p)
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestProxy runs an ephemeral sing-box instance to test the given proxy (compatibility wrapper).
func TestProxy(ctx context.Context, p *Proxy, singboxPath string) (*TestResult, error) {
	return TestProxyWithOptions(ctx, p, TestOptions{
		SingboxPath: singboxPath,
	})
}

// TestProxyWithOptions runs an ephemeral sing-box instance to test the given proxy with specified options.
func TestProxyWithOptions(ctx context.Context, p *Proxy, opts TestOptions) (*TestResult, error) {
	singboxPath := opts.SingboxPath
	if singboxPath == "" {
		singboxPath = "sing-box"
	}

	// 1. Pick a free local port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to allocate free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	// 2. Build minimal sing-box ephemeral config
	outbound := p.ToSingboxOutbound("proxy")
	if opts.VethIF != "" {
		outbound["bind_interface"] = opts.VethIF
	}

	routeCfg := map[string]interface{}{
		"final": "proxy",
	}
	if opts.VethIF != "" {
		routeCfg["default_interface"] = opts.VethIF
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "warn",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": port,
			},
		},
		"outbounds": []interface{}{
			outbound,
		},
	}

	if opts.ContainerGW != "" {
		cfg["dns"] = map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"tag":         "dns-bootstrap",
					"type":        "udp",
					"server":      opts.ContainerGW,
					"server_port": 53,
				},
			},
			"final":    "dns-bootstrap",
			"strategy": "ipv4_only",
		}
		routeCfg["default_domain_resolver"] = "dns-bootstrap"
	}

	cfg["route"] = routeCfg

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal test config: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "singbox-test-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp config file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(cfgBytes); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("failed to write test config file: %w", err)
	}
	_ = tmpFile.Close()

	// 3. Validate with sing-box check
	checkCmd := exec.CommandContext(ctx, singboxPath, "check", "-c", tmpPath)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		res := &TestResult{
			Status:   "error",
			Error:    sanitizeError(fmt.Sprintf("sing-box check failed: %s", string(out))),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	// 4. Start child process with captured stderr
	runCtx, cancelRun := context.WithTimeout(ctx, 22*time.Second)
	defer cancelRun()

	runCmd := exec.CommandContext(runCtx, singboxPath, "run", "-c", tmpPath)
	stderrBuf := &boundedBuffer{max: 4096}
	runCmd.Stderr = stderrBuf

	procExited := make(chan error, 1)

	if err := runCmd.Start(); err != nil {
		res := &TestResult{
			Status:   "error",
			Error:    sanitizeError(fmt.Sprintf("failed to start test sing-box: %v", err)),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	go func() {
		procExited <- runCmd.Wait()
	}()

	defer func() {
		if runCmd.Process != nil {
			_ = runCmd.Process.Kill()
		}
		select {
		case <-procExited:
		case <-time.After(1 * time.Second):
		}
	}()

	// 5. Poll until local proxy port is open (60 * 100ms = 6.0s)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 60; i++ {
		// Check if process exited early
		select {
		case exitErr := <-procExited:
			stderrMsg := strings.TrimSpace(stderrBuf.String())
			if stderrMsg == "" && exitErr != nil {
				stderrMsg = exitErr.Error()
			}
			res := &TestResult{
				Status:   "error",
				Error:    sanitizeError(fmt.Sprintf("test sing-box exited prematurely: %s", stderrMsg)),
				TestedAt: time.Now(),
			}
			p.LastTest = res
			return res, nil
		default:
		}

		conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ready {
		stderrMsg := strings.TrimSpace(stderrBuf.String())
		errMsg := "test sing-box failed to bind to port in time"
		if stderrMsg != "" {
			errMsg = fmt.Sprintf("%s: %s", errMsg, stderrMsg)
		}
		res := &TestResult{
			Status:   "error",
			Error:    sanitizeError(errMsg),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	// 6. Connect through proxy with 10s HTTP timeout
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	var lastErr string

	start := time.Now()
	// Try ip-api.com first
	req, err := http.NewRequestWithContext(runCtx, http.MethodGet, "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query", nil)
	if err != nil {
		res := &TestResult{
			Status:   "error",
			Error:    sanitizeError(err.Error()),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	resp, err := httpClient.Do(req)
	latency := time.Since(start).Milliseconds()

	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var apiResp ipAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err == nil && apiResp.Status == "success" {
			res := &TestResult{
				Status:      "ok",
				ExitIP:      apiResp.Query,
				Country:     apiResp.Country,
				CountryCode: apiResp.CountryCode,
				City:        apiResp.City,
				ISP:         apiResp.ISP,
				LatencyMs:   latency,
				TestedAt:    time.Now(),
			}
			p.LastTest = res
			return res, nil
		}
		if apiResp.Status != "success" && apiResp.Status != "" {
			lastErr = fmt.Sprintf("ip-api returned status %s", apiResp.Status)
		}
	} else if err != nil {
		lastErr = err.Error()
	} else {
		lastErr = fmt.Sprintf("ip-api returned HTTP %d", resp.StatusCode)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Fallback to api.ipify.org
	start = time.Now()
	req2, err := http.NewRequestWithContext(runCtx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err == nil {
		resp2, err2 := httpClient.Do(req2)
		latency = time.Since(start).Milliseconds()
		if err2 == nil && resp2.StatusCode == http.StatusOK {
			defer resp2.Body.Close()
			var ipify ipifyResponse
			if err := json.NewDecoder(resp2.Body).Decode(&ipify); err == nil && ipify.IP != "" {
				res := &TestResult{
					Status:    "ok",
					ExitIP:    ipify.IP,
					LatencyMs: latency,
					TestedAt:  time.Now(),
				}
				p.LastTest = res
				return res, nil
			}
			lastErr = "invalid response from api.ipify.org"
		} else if err2 != nil {
			lastErr = err2.Error()
		} else {
			lastErr = fmt.Sprintf("api.ipify.org returned HTTP %d", resp2.StatusCode)
		}
		if resp2 != nil {
			_ = resp2.Body.Close()
		}
	} else {
		lastErr = err.Error()
	}

	if lastErr == "" {
		lastErr = "connection failed or timed out"
	}

	res := &TestResult{
		Status:   "error",
		Error:    sanitizeError(lastErr),
		TestedAt: time.Now(),
	}
	p.LastTest = res
	return res, nil
}
