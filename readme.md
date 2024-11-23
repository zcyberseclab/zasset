# zasset

[![Go Report Card](https://goreportcard.com/badge/github.com/zcyberseclab/zasset)](https://goreportcard.com/report/github.com/zcyberseclab/zasset)
[![GoDoc](https://godoc.org/github.com/zcyberseclab/zasset?status.svg)](https://godoc.org/github.com/zcyberseclab/zasset)
[![License](https://img.shields.io/github/license/zcyberseclab/zasset)](https://github.com/zcyberseclab/zasset/blob/main/LICENSE)

A fast, customizable service detection tool powered by a flexible fingerprint system. It helps you identify services, APIs, and network configurations across your infrastructure.

<h4 align="center">
  <a href="https://github.com/zcyberseclab/zasset/wiki">Documentation</a> |
  <a href="#-features">Features</a> |
  <a href="#-installation">Installation</a> |
  <a href="#-usage">Usage</a>
</h4>

## ✨ Features

### Asset Discovery & Management
- Comprehensive internal network asset identification
- Service enumeration
- MAC address detection
- Operating system fingerprinting
- IoT device recognition

### Risk Assessment
- Vulnerability analysis
- Port exposure risk evaluation
- Security configuration auditing

### Detection Methods
Multiple detection technologies integrated:
- ZScan core scanning
- Passive traffic analysis
- PING detection
- IoT protocol scanning
- SNMP protocol detection
- DECRPC detection
- Camera device discovery
- ARP detection

### Key Advantages
- High-speed scanning capabilities
- Accurate asset identification
- Rich vulnerability POC database

## 📦 Installation

### From Binary

Download the latest version from [Releases](https://github.com/zcyberseclab/zasset/releases)

## 🚀 Usage

### Command Line Usage

```bash
 
zasset --target 192.168.1.0/24

# Use custom config file
zasset --target 192.168.1.1 --config /path/to/config.yaml

# Use custom templates directory
zasset --target 192.168.1.1 --templates-dir /path/to/templates

# Show version information
zasset --version
```

### Passive Detection Mode

```bash
# Continuous monitoring mode
zasset passive --interface eth0 --report-type http --report-url http://your-api.com/report

# Time-limited monitoring (30 seconds)
zasset passive --interface eth0 --duration 30s --report-type db --db-dsn "user:pass@tcp(127.0.0.1:3306)/dbname"

# Combined with active scanning
zasset --target 192.168.1.0/24 --enable-passive --passive-duration 30s
```

### Configuration Example

```yaml
passive_detector:
  # Network interface to monitor
  interface: eth0
  
  # Report configuration
  report:
    # Available types: http, database, console
    type: http
    # HTTP reporter settings
    http:
      url: http://your-api.com/report
      headers:
        Authorization: "Bearer your-token"
    # Database reporter settings
    database:
      driver: mysql  # or postgresql
      dsn: "user:pass@tcp(127.0.0.1:3306)/dbname"
  
  # Optional: Duration for time-limited detection
  # Format: 30s, 1m, 1h, etc. Empty for continuous mode
  duration: "30s"
```

### Using as a Go Library

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	zasset "github.com/zcyberseclab/zasset/pkg"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	CommitSHA = "unknown"
)

func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("portconfig", "config/port_config.yaml", "Path to config file")
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

	scanner := zasset.NewScanner(&zasset.ScannerConfig{
		ConfigPath:   *configPath,
		TemplatesDir: *templatesDir,
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

```
## How to build oui.txt
```bash
gzip -9 oui.txt
```
it will generate oui.txt.gz file, put it in the pkg directory.

The format of oui.txt.gz is as follows:
```
FCF528 Zyxel Communications Corporation
FCF5C4 Espressif Inc.
FCF647 Fiberhome Telecommunication Technologies Co.
FCF763 KunGao Micro (JiangSu) Co.
FCF77B Huawei Device Co.
```

## Our Mission
 


## Contributors
Thanks to all the amazing community contributors for sending PRs and keeping this project updated. ❤️
<a href="https://github.com/zcyberseclab/zasset/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zcyberseclab/zasset" />
</a>

## License
zasset is distributed under MIT License.
