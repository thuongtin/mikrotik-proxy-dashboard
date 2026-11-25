package singbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// Redact sensitive patterns from sing-box logs
	passwordRegex = regexp.MustCompile(`(?i)(password|pass|secret|uuid|token|pbk|sid)[=:\s"]+([^\s,"]+)`)
)

// SupervisorStatus reports sing-box engine status.
type SupervisorStatus struct {
	Running     bool      `json:"running"`
	PID         int       `json:"pid"`
	Version     string    `json:"version"`
	LastReload  time.Time `json:"lastReload"`
	LastError   string    `json:"lastError,omitempty"`
	ConfigPath  string    `json:"configPath"`
}

// Supervisor manages the sing-box daemon lifecycle and sanitized log ring-buffer.
type Supervisor struct {
	mu          sync.Mutex
	singboxPath string
	configPath  string
	version     string
	cmd         *exec.Cmd
	running     bool
	lastReload  time.Time
	lastError   string
	cancelRun   context.CancelFunc

	logMu       sync.Mutex
	logRing     []string
	maxLogLines int

	stopChan chan struct{}
	procDone chan struct{}
}

// NewSupervisor creates a sing-box supervisor.
func NewSupervisor(singboxPath, dataDir string) *Supervisor {
	if singboxPath == "" {
		singboxPath = "sing-box"
	}
	configPath := filepath.Join(dataDir, "sing-box.json")

	// Query version
	ver := "unknown"
	cmd := exec.Command(singboxPath, "version")
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			ver = strings.TrimSpace(lines[0])
		}
	}

	return &Supervisor{
		singboxPath: singboxPath,
		configPath:  configPath,
		version:     ver,
		maxLogLines: 200,
		logRing:     make([]string, 0, 200),
	}
}

// ApplyConfig atomically checks and writes new config, then restarts sing-box.
func (s *Supervisor) ApplyConfig(cfgBytes []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Write to temp file
	tmpFile, err := os.CreateTemp(filepath.Dir(s.configPath), "singbox-cfg-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create tmp config file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(cfgBytes); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write tmp config: %w", err)
	}
	_ = tmpFile.Close()

	// 2. Validate with sing-box check
	checkCmd := exec.Command(s.singboxPath, "check", "-c", tmpPath)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		errMsg := fmt.Sprintf("sing-box check failed: %s", string(out))
		s.lastError = errMsg
		return errors.New(errMsg)
	}

	// 3. Rename atomically
	if err := os.Rename(tmpPath, s.configPath); err != nil {
		return fmt.Errorf("failed to rename config file: %w", err)
	}

	s.lastReload = time.Now()
	s.lastError = ""

	// 4. Restart process
	s.stopLocked()
	return s.startLocked()
}

// Start launches the supervisor daemon.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Supervisor) startLocked() error {
	if s.running {
		return nil
	}

	// Verify config file exists
	if _, err := os.Stat(s.configPath); os.IsNotExist(err) {
		return fmt.Errorf("sing-box config not found at %s", s.configPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelRun = cancel
	s.stopChan = make(chan struct{})
	s.procDone = make(chan struct{})

	cmd := exec.CommandContext(ctx, s.singboxPath, "run", "-c", s.configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return err
	}

	if err := cmd.Start(); err != nil {
		cancel()
		s.lastError = err.Error()
		return err
	}

	s.cmd = cmd
	s.running = true

	// Stream logs
	go s.captureLogs(stdout)
	go s.captureLogs(stderr)

	// Monitor child process for unexpected exit
	go s.monitorProcess(cmd, s.stopChan, s.procDone)

	return nil
}

func (s *Supervisor) captureLogs(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()
		sanitized := passwordRegex.ReplaceAllString(text, "$1=***")
		s.appendLog(sanitized)
	}
}

func (s *Supervisor) appendLog(line string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	formatted := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
	if len(s.logRing) >= s.maxLogLines {
		s.logRing = append(s.logRing[1:], formatted)
	} else {
		s.logRing = append(s.logRing, formatted)
	}
}

func (s *Supervisor) monitorProcess(cmd *exec.Cmd, stopChan, procDone chan struct{}) {
	err := cmd.Wait()
	close(procDone)

	select {
	case <-stopChan:
		// Clean stop requested
		return
	default:
	}

	s.mu.Lock()
	s.running = false
	if err != nil {
		s.lastError = fmt.Sprintf("sing-box process exited: %v", err)
		s.appendLog(fmt.Sprintf("ERROR: sing-box process died: %v, attempting restart in 3s...", err))
	} else {
		s.appendLog("sing-box process exited cleanly")
	}
	s.mu.Unlock()

	// Auto-restart with backoff in background
	go func() {
		time.Sleep(3 * time.Second)
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.running {
			_ = s.startLocked()
		}
	}()
}

// Stop terminates the running sing-box process.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *Supervisor) stopLocked() {
	if !s.running {
		return
	}

	if s.stopChan != nil {
		close(s.stopChan)
		s.stopChan = nil
	}

	if s.cancelRun != nil {
		s.cancelRun()
	}

	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}

	done := s.procDone
	s.running = false
	s.cmd = nil
	s.procDone = nil

	if done != nil {
		s.mu.Unlock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		s.mu.Lock()
	}
}

// GetStatus returns current supervisor telemetry.
func (s *Supervisor) GetStatus() SupervisorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	pid := 0
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}

	return SupervisorStatus{
		Running:    s.running,
		PID:        pid,
		Version:    s.version,
		LastReload: s.lastReload,
		LastError:  s.lastError,
		ConfigPath: s.configPath,
	}
}

// GetLogs returns a copy of sanitized logs from the ring buffer.
func (s *Supervisor) GetLogs() []string {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	res := make([]string, len(s.logRing))
	copy(res, s.logRing)
	return res
}
