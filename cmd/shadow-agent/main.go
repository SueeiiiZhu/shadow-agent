// Command shadow-agent is the Shadow Panel data-plane / node-core binary. It
// generates proxy-kernel configs, supervises kernel processes, and exposes an
// HTTPS REST control surface secured by a per-agent bearer token.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SueeiiiZhu/shadow-agent/internal/api"
	"github.com/SueeiiiZhu/shadow-agent/internal/config"
	"github.com/SueeiiiZhu/shadow-agent/internal/process"
)

func main() {
	configPath := flag.String("config", "", "path to JSON config file (optional; env overrides apply)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("shadow-agent: %v", err)
	}

	sup := process.New(cfg.DataDir, cfg.KernelBinDir)
	srv := api.New(cfg, sup)

	httpSrv, err := srv.HTTPServer()
	if err != nil {
		log.Fatalf("shadow-agent: build server: %v", err)
	}
	httpSrv.Addr = cfg.Listen

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// shutdownDone is closed once the shutdown sequence (HTTP drain + kernel
	// child termination) has fully completed, so main() can wait for it and not
	// exit while kernel processes are still being killed.
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Println("shadow-agent: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		sup.Shutdown()
		close(shutdownDone)
	}()

	if cfg.Token == "" {
		log.Println("shadow-agent: WARNING no token configured; all authenticated endpoints will return 401")
	}
	log.Printf("shadow-agent %s listening on %s (TLS)", api.Version, cfg.Listen)

	// Certificates are embedded in the server's TLSConfig, so pass empty paths.
	err = httpSrv.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		// Startup/serve failure that is not a graceful close: the shutdown
		// goroutine is still parked on ctx.Done(), so tear down kernels directly.
		log.Printf("shadow-agent: server error: %v", err)
		sup.Shutdown()
		os.Exit(1)
	}
	// Graceful close: wait for the shutdown goroutine to finish killing kernels
	// before returning, so no child process is orphaned.
	<-shutdownDone
}
