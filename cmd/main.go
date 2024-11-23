package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	zasset "github.com/zcyberseclab/zasset/pkg"
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

					if isPrivateIP(ipv4) {
						networks = append(networks, ipnet.String())
					}
				}
			}
		}
	}
	return networks, nil
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsPrivate() {

		return true
	}

	return false
}

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("portconfig", "config/port_config.yaml", "Path to port config file")
	templatesDir := flag.String("templates", "templates", "Path to templates directory")
	versionFlag := flag.Bool("version", false, "Show version information")

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

	if *target == "" {

		networks, err := getLocalNetworks()
		if err != nil {
			log.Fatalf("failed to get local networks: %v", err)
		}
		if len(networks) == 0 {
			log.Fatal("no available internal network segments found")
		}
		*target = strings.Join(networks, ",")
		log.Printf("discovered network segments: %s\n", *target)
	}

	startTime := time.Now()

	scanner := zasset.NewScanner(&zasset.ScannerConfig{
		ConfigPath:   *configPath,
		TemplatesDir: *templatesDir,
		ReportURL:    *reportURL,
		DBType:       *dbType,
		DBDSN:        *dbDSN,
	})
	nodes, err := scanner.StartScan(*target)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
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
