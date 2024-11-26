package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"

	// Local imports should be in a separate group
	zasset "github.com/zcyberseclab/zasset/pkg"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func main() {
	target := flag.String("target", "", "CIDR ranges to scan (comma-separated)")
	configPath := flag.String("portconfig", "config/port_config.yaml", "Path to port config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	versionFlag := flag.Bool("version", false, "Show version information")
	networkCard := flag.String("interface", "", "Network interface to use")
	//passiveTimeout := flag.Int("passive-timeout", 60, "Timeout for passive scanning in seconds (0 for no timeout)")

	dbType := flag.String("db-type", "", "Database type (mysql/postgres/sqlite)")
	dbDSN := flag.String("db-dsn", "", "Database connection string")
	reportURL := flag.String("report-url", "", "URL for reporting results")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", CommitSHA)
		return
	}

	baseConfig := &zasset.ScannerConfig{
		ConfigPath:   *configPath,
		TemplatesDir: *templatesDir,
		NetworkCard:  *networkCard,
	}

	reporterConfig := &zasset.ReporterConfig{
		EnableConsole: true,
		HTTPEndpoint:  *reportURL,
		Driver:        *dbType,
		DSN:           *dbDSN,
	}

	if err := zasset.InitMultiReporter(reporterConfig); err != nil {
		log.Fatalf("Failed to initialize multi-reporter: %v", err)
	}

	activeCfg := *baseConfig
	activeCfg.ScannerType = zasset.ActiveScanner
	activeScanner := zasset.NewScanner(&activeCfg)

	//passiveCfg := *baseConfig
	//passiveCfg.ScannerType = zasset.PassiveScanner
	//passiveCfg.PassiveTimeout = *passiveTimeout
	//passiveScanner := zasset.NewScanner(&passiveCfg)

	var results []stage.Node
	startTime := time.Now()

	// Add timing statistics
	timings := make(map[string]time.Duration)

	// Track target preparation time
	targetStartTime := time.Now()
	var targets []string
	if *target != "" {
		targets = strings.Split(*target, ",")
		for i, t := range targets {
			targets[i] = strings.TrimSpace(t)
		}
		log.Printf("Using user-specified targets: %v", targets)
	} else {
		networks, err := zasset.GetLocalNetworks()
		if err != nil {
			log.Fatalf("Failed to get local networks: %v", err)
		}
		if len(networks) == 0 {
			log.Fatal("No available internal network segments found")
		}
		targets = networks
		log.Printf("Using auto-discovered network segments: %v", targets)
	}
	timings["target_preparation"] = time.Since(targetStartTime)

	log.Printf("Targets to scan: %v", targets)

	// Start passive scanner if configured
	//if passiveScanner != nil {
	//	passiveNodes, err := passiveScanner.Start(nil)
	//	if err != nil {
	//		log.Printf("Warning: Passive scanner failed: %v", err)
	//	} else {
	// results = append(results, passiveNodes...)
	//		log.Printf("[Main] Passive scanner started, found %d nodes", len(passiveNodes))
	//	}
	//}

	// Track active scanning time
	scanStartTime := time.Now()

	// Create a done channel for scan completion
	done := make(chan struct{})

	// Start scanning in a goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in active scanner: %v", r)
				debug.PrintStack()
				done <- struct{}{}
				return
			}
		}()

		if activeScanner != nil {
			activeNodes, err := activeScanner.Start(targets)
			if err != nil {
				log.Printf("Active scanner failed: %v", err)
			} else {
				results = append(results, activeNodes...)
			}
		}
		done <- struct{}{}
	}()

	// Handle interrupts and timeouts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("\nReceived interrupt signal, stopping scanners...")
		if activeScanner != nil {
			activeScanner.Stop()
		}
	case <-done:
		log.Println("\nScan completed successfully")
	}

	timings["active_scanning"] = time.Since(scanStartTime)

	// Update summary section with timing details
	totalDuration := time.Since(startTime)
	log.Printf("\n=== Scan Summary ===")
	log.Printf("Total Scan Duration: %v", totalDuration)
	log.Printf("Target Preparation Time: %v", timings["target_preparation"])
	log.Printf("Active Scanning Time: %v", timings["active_scanning"])
	log.Printf("Total Nodes Discovered: %d", len(results))
}
