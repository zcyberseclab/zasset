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

## ✨Features

- **Fast Scanning Engine**: High-performance concurrent scanning
- **Precise POC targeting**: 
  - High-precision POC targeting via fingerprinting, faster and more accurate than traditional scanners
- **Third-party Integration**:
  - Censys integration for extended scanning
  - Additional threat intelligence support
- **Flexible Fingerprint System**: 
  - Custom fingerprint definition support
  - Multiple protocol support (HTTP, HTTPS, TCP)
  - Pattern matching and response analysis
- **Service Detection**:
  - Web service identification
  - Common application framework detection
  - TLS/SSL configuration analysis
- **Plugin System**:
  - Extensible plugin architecture
  - Hot-reload support
  - Multi-language plugin support (Lua, YAML)
- **Output Formats**:
  - JSON output for integration
  - Human-readable console output
  - Custom report generation

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

# Enable geolocation lookup
zasset --target 192.168.1.1 --geo

# Use Censys integration
zasset --target 192.168.1.1 --censys --censys-api-key <your-key> --censys-secret <your-secret>

# Show version information
zasset --version
```

### Using as a Go Library

```go
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/zcyberseclab/zasset/pkg/stage"
)
func main() {
	target := flag.String("target", "", "IP address or CIDR range to scan")
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	templatesDir := flag.String("templates-dir", "templates", "Path to templates directory")
	 
	flag.Parse()

	if *target == "" {
		log.Fatal("CIDR range is required")
	}
 
 
	scanner, err := stage.NewScanner(*configPath, *templatesDir, *enableGeo, *enableCensys, *censysAPIKey, *censysSecret)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	// Perform scan
	startTime := time.Now()
	results, err := scanner.Scan(*target)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print results
	if err := stage.PrintResults(results); err != nil {
		log.Printf("Error printing results: %v", err)
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
