package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

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

// TestProxy runs an ephemeral sing-box instance to test the given proxy.
func TestProxy(ctx context.Context, p *Proxy, singboxPath string) (*TestResult, error) {
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
			p.ToSingboxOutbound("proxy"),
		},
		"route": map[string]interface{}{
			"final": "proxy",
		},
	}

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
			Error:    fmt.Sprintf("sing-box check failed: %s", string(out)),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	// 4. Start child process
	runCtx, cancelRun := context.WithTimeout(ctx, 15*time.Second)
	defer cancelRun()

	runCmd := exec.CommandContext(runCtx, singboxPath, "run", "-c", tmpPath)
	if err := runCmd.Start(); err != nil {
		res := &TestResult{
			Status:   "error",
			Error:    fmt.Sprintf("failed to start test sing-box: %v", err),
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	defer func() {
		if runCmd.Process != nil {
			_ = runCmd.Process.Kill()
			_ = runCmd.Wait()
		}
	}()

	// 5. Poll until local proxy port is open
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !ready {
		res := &TestResult{
			Status:   "error",
			Error:    "test sing-box failed to bind to port in time",
			TestedAt: time.Now(),
		}
		p.LastTest = res
		return res, nil
	}

	// 6. Connect through proxy with 10s timeout
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	start := time.Now()
	// Try ip-api.com first
	req, err := http.NewRequestWithContext(runCtx, http.MethodGet, "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query", nil)
	if err != nil {
		res := &TestResult{
			Status:   "error",
			Error:    err.Error(),
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
		}
		if resp2 != nil {
			_ = resp2.Body.Close()
		}
	}

	res := &TestResult{
		Status:   "error",
		Error:    errors.New("connection failed or timed out").Error(),
		TestedAt: time.Now(),
	}
	p.LastTest = res
	return res, nil
}
