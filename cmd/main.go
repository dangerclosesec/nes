// main exec file for fob
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dangerclosesec/nes"
	"github.com/dangerclosesec/nes/internal/api"
	"github.com/dangerclosesec/nes/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// configFile is the path to the target configuration file
	configFile string

	// Management API configuration
	withManagement     bool
	withManagementAddr string

	// Metrics configuration
	withMetrics     bool
	withMetricsAddr string

	// LogFile configuration
	withLogFile     bool
	withLogFilePath string

	// StreamLog configuration
	withStreamLog string

	// LogFile configuration
	withLoadbalancer        bool
	withLoadbalancerAddr    string
	withLoadbalancerTls     bool
	withLoadbalancerTlsAddr string

	//
	log = stdlog.New(os.Stdout, "\033[38;5;239m[ \033[38;5;2mn\033[38;5;214me\033[38;5;200ms    \033[38;5;239m] \033[0m", stdlog.LstdFlags|stdlog.Lmsgprefix|stdlog.Lmicroseconds)
)

// Add health metrics
func init() {
	flag.StringVar(&configFile, "f", "config.yml", "Configuration file to pass")

	flag.BoolVar(&withManagement, "with-mgmt", true, "")
	flag.StringVar(&withManagementAddr, "with-mgmt-addr", ":7841", "")

	flag.BoolVar(&withMetrics, "with-metrics", true, "")
	flag.StringVar(&withMetricsAddr, "with-metrics-addr", ":9090", "")

	flag.BoolVar(&withLogFile, "with-logfile", true, "")
	flag.StringVar(&withLogFilePath, "with-logfile-path", "./n8s.log", "")

	flag.StringVar(&withStreamLog, "with-streamlog", "", "")

	flag.BoolVar(&withLoadbalancer, "with-lb", true, "")
	flag.StringVar(&withLoadbalancerAddr, "with-lb-addr", ":80", "")
	flag.BoolVar(&withLoadbalancerTls, "with-lb-tls", true, "")
	flag.StringVar(&withLoadbalancerTlsAddr, "with-lb-tls-addr", ":443", "")

	flag.Parse()

	if withMetrics {
		prometheus.MustRegister(metrics.ServiceCount)
		prometheus.MustRegister(metrics.ServiceContainerCount)
	}
}

// main
func main() {
	log.Printf("Starting n8s")

	// Create context with cancellation for the entire application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := []nes.Option{}

	if withStreamLog != "" {
		opts = append(opts, nes.WithStreamLogs())
	}

	if withLogFile {
		opts = append(opts, nes.WithLogFile(withLogFilePath))
	}

	mgr, err := nes.NewManager(ctx, configFile, opts...)
	if err != nil {
		log.Fatalf("failed %s", err)
	}
	defer mgr.Cleanup()

	if withManagement {
		log.Printf("Starting management api on %s\n", withManagementAddr)
		go func() {
			server := &http.Server{
				Addr:    withManagementAddr,
				Handler: api.Handler(mgr),
			}

			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("Server failed: %v", err)
			}
		}()
	}

	if withMetrics {
		log.Printf("Starting metrics server on %s\n", withMetricsAddr)
		go func() {
			server := &http.Server{
				Addr:    withMetricsAddr,
				Handler: promhttp.Handler(),
			}

			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("Server failed: %v", err)
			}
		}()
	}

	// Ugly pattern, but momma always said it could grow up to do great things.
	if withLoadbalancer || withLoadbalancerTls {
		log.Println("Starting loadbalancer")

		lbOpts := []nes.LoadBalancerOption{}
		if withLoadbalancer {
			log.Printf("Starting loadbalancer on %s\n", withLoadbalancerAddr)
			lbOpts = append(lbOpts, nes.LoadBalancerWithHttp(withLoadbalancerAddr))
		}

		if withLoadbalancerTls {
			log.Printf("Starting tls loadbalancer on %s\n", withLoadbalancerTlsAddr)
			lbOpts = append(lbOpts, nes.LoadBalancerWithTls(withLoadbalancerTlsAddr, &tls.Config{}))
		}

		if err := mgr.StartLoadBalancer(lbOpts...); err != nil {
			log.Fatalf("failed to start loadbalancer with error: %v", err)
		}
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGABRT)

	// Start services
	if err := mgr.StartServices(); err != nil {
		log.Printf("Error starting services: %v", err)
		cancel()
		// Initiate graceful shutdown
		shutdownTimeout := 30 * time.Second
		if err := gracefulShutdown(mgr, shutdownTimeout); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
		os.Exit(1)
	}

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal '%v', initiating graceful shutdown...", sig)

	// Cancel context to notify all components
	cancel()

	log.Println("Goodbye")
}

func gracefulShutdown(mgr *nes.Manager, timeout time.Duration) error {
	// Create a channel to signal completion
	done := make(chan struct{})

	// Create timeout context
	toCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		// Stop docker services
		if err := mgr.StopServices(); err != nil {
			log.Printf("Error stopping services: %v", err)
		}

		close(done)
	}()

	// Wait for either completion or timeout
	select {
	case <-toCtx.Done():
		if toCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("shutdown timed out after %v", timeout)
		}
	case <-done:
		log.Println("Graceful shutdown completed")
	}

	return nil
}
