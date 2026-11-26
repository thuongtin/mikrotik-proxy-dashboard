package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/auth"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/mikrotik"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
	internalweb "github.com/thuongtin/mikrotik-proxy-dashboard/internal/web"
	webfs "github.com/thuongtin/mikrotik-proxy-dashboard/web"
)

var (
	version = "1.0.0"
)

func main() {
	hashFlag := flag.Bool("hash-password", false, "Read password from stdin and print bcrypt hash")
	versionFlag := flag.Bool("version", false, "Print application version")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("proxy-dash version %s\n", version)
		os.Exit(0)
	}

	if *hashFlag {
		handleHashPassword()
		return
	}

	cfg := config.LoadFromEnv()
	// Before any child process starts: extensions may drop secrets from the
	// environment so that sing-box does not inherit them.
	ext := loadExtensions(cfg)

	if cfg.DashboardPasswordHash == "" {
		log.Println("WARNING: DASHBOARD_PASSWORD_HASH environment variable is not set!")
		log.Println("To generate a secure password hash, run: proxy-dash --hash-password")
	}

	// 1. Initialize persistent state
	st, err := state.Load(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize state: %v", err)
	}

	// 2. Initialize authentication manager
	authMgr, err := auth.NewAuthManager(cfg.DataDir, cfg.DashboardPasswordHash)
	if err != nil {
		log.Fatalf("Failed to initialize auth manager: %v", err)
	}

	// 3. Initialize sing-box supervisor
	sup := singbox.NewSupervisor(cfg.SingboxPath, cfg.DataDir)
	defer sup.Stop()

	// Generate and apply initial sing-box configuration
	initialCfg, err := singbox.GenerateConfig(cfg, st)
	if err != nil {
		log.Printf("Warning: failed to generate initial sing-box config: %v", err)
	} else {
		if err := sup.ApplyConfig(initialCfg); err != nil {
			log.Printf("Warning: failed to apply initial sing-box config: %v", err)
		} else {
			log.Println("sing-box engine initialized and running successfully")
		}
	}

	// 4. Initialize MikroTik REST API client
	if cfg.MikroTikInsecureTLS {
		log.Println("WARNING: MIKROTIK_INSECURE_TLS=true, the RouterOS certificate is NOT verified. Set MIKROTIK_CA_FILE instead.")
	}
	if cfg.MikroTikUser == "admin" {
		log.Println("WARNING: MIKROTIK_USER is 'admin'. Use a dedicated RouterOS user with a restricted group.")
	}
	mkClient, err := mikrotik.NewClient(cfg.MikroTikURL, cfg.MikroTikUser, cfg.MikroTikPass, mikrotik.Options{
		InsecureTLS: cfg.MikroTikInsecureTLS,
		CAFile:      cfg.MikroTikCAFile,
	})
	if err != nil {
		mkClient = nil
		log.Printf("ERROR: cannot initialize the RouterOS client, device and status pages will return 503 until this is fixed: %v", err)
	} else {
		// Run initial reconciliation with RouterOS in background
		go func() {
			time.Sleep(2 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := mkClient.Reconcile(ctx, st); err != nil {
				log.Printf("RouterOS initial reconciliation FAILED, router rules may not match saved assignments: %v", err)
			} else {
				log.Println("RouterOS rules reconciled successfully")
			}
		}()
	}

	// 5. Initialize Web HTTP server
	staticFS := webfs.GetStaticFS()
	srv := internalweb.NewServer(cfg, authMgr, st, sup, mkClient, staticFS)

	// 6. Optional features of this edition.
	stopExt := ext.start(srv)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	// Channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Starting mikrotik-proxy-dashboard on %s...", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	stopExt()
	sup.Stop()
	log.Println("proxy-dash exited cleanly")
}

func handleHashPassword() {
	stat, _ := os.Stdin.Stat()
	var pass string
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// Reading from interactive terminal
		fmt.Print("Enter password to hash: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			pass = strings.TrimSpace(scanner.Text())
		}
	} else {
		// Reading from pipe / stdin
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			pass = strings.TrimSpace(scanner.Text())
		}
	}

	if pass == "" {
		fmt.Fprintln(os.Stderr, "Error: empty password")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating bcrypt hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hash)
}
