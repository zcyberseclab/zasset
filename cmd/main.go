package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	zasset "github.com/zcyberseclab/zasset/pkg"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

// Get local available internal network segments
func getLocalNetworks() ([]string, error) {
	var networks []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {

		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {

					if ipv4.IsPrivate() {
						networks = append(networks, ipnet.String())
					}
				}
			}
		}
	}
	return networks, nil
}

func main() {
	target := flag.String("target", "", "CIDR ranges to scan (comma-separated)")
	configPath := flag.String("portconfig", "config/port_config.yaml", "Path to port config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	versionFlag := flag.Bool("version", false, "Show version information")
	networkCard := flag.String("interface", "", "Network interface to use")
	passiveTimeout := flag.Int("passive-timeout", 60, "Timeout for passive scanning in seconds (0 for no timeout)")

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

	// 准备基础配置
	baseConfig := &zasset.ScannerConfig{
		ConfigPath:   *configPath,
		TemplatesDir: *templatesDir,
		ReportURL:    *reportURL,
		DBType:       *dbType,
		DBDSN:        *dbDSN,
		NetworkCard:  *networkCard,
	}

	activeCfg := *baseConfig
	activeCfg.ScannerType = zasset.ActiveScanner
	activeScanner := zasset.NewScanner(&activeCfg)

	//passiveCfg := *baseConfig
	//passiveCfg.ScannerType = zasset.PassiveScanner
	//passiveCfg.PassiveTimeout = *passiveTimeout
	//passiveScanner := zasset.NewScanner(&passiveCfg)

	// 准备结果收集
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
		networks, err := getLocalNetworks()
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
		if activeScanner != nil {
			activeNodes, err := activeScanner.Start(targets)
			if err != nil {
				log.Printf("Active scanner failed: %v", err)
			} else {
				results = append(results, activeNodes...)
				log.Printf("[Main] Active scanner completed, found %d nodes", len(activeNodes))
			}
		}
		done <- struct{}{} // 只在扫描真正完成后发送信号
	}()

	// Handle interrupts and timeouts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("\nReceived interrupt signal, stopping scanners...")
		if activeScanner != nil {
			activeScanner.Stop() // 确保调用Stop方法清理资源
		}
	case <-time.After(time.Duration(*passiveTimeout) * time.Second):
		if *passiveTimeout > 0 {
			log.Println("\nPassive scan timeout reached, stopping scanners...")
			if activeScanner != nil {
				activeScanner.Stop()
			}
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

	// Print detailed results
	log.Printf("\n=== Detailed Results ===")
	for i, node := range results {
		log.Printf("\nNode #%d:", i+1)
		log.Printf("  IP: %s", node.IP)
		log.Printf("  MAC: %s", node.MAC)
		if node.Hostname != "" {
			log.Printf("  Hostname: %s", node.Hostname)
		}
		if node.Manufacturer != "" {
			log.Printf("  Manufacturer: %s", node.Manufacturer)
		}

		log.Printf("  ---")
	}
}
