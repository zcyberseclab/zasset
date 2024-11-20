package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/zcyberseclab/zscan/pkg/zasset"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	versionFlag := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", CommitSHA)
		return
	}

	if *target == "" {
		log.Fatal("Target is required")
	}

	startTime := time.Now()

	detector := &zasset.BaseDetector{
		timeout: 5 * time.Second,
	}

	nodes, err := detector.Detect(*target)
	if err != nil {
		log.Fatalf("Detection failed: %v", err)
	}

	for _, node := range nodes {
		fmt.Printf("Found host: %s\n", node.IP)
		if node.Hostname != "" {
			fmt.Printf("  Hostname: %s\n", node.Hostname)
		}
		if len(node.Ports) > 0 {
			fmt.Printf("  Open ports: %s\n", zasset.ServiceInfoToString(node.Ports))
		}
	}

	duration := time.Since(startTime)
	log.Printf("\nScan completed in: %v\n", duration)
}
