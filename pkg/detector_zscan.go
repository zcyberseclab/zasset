package zasset

import (
	"log"
	"net"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

// ZScanDetector zscan探测器
type ZScanDetector struct {
	BaseDetector
	configPath   string
	templatesDir string
}

// NewZScanDetector 创建新的ZScan探测器
func NewZScanDetector(config *ScannerConfig) *ZScanDetector {
	return &ZScanDetector{
		BaseDetector: BaseDetector{},
		configPath:   config.ConfigPath,
		templatesDir: config.TemplatesDir,
	}
}

func (z *ZScanDetector) Name() string {
	return "ZScanDetector"
}

func (z *ZScanDetector) Detect(target string) ([]stage.Node, error) {
	log.Printf("\n[ZScanDetector] ========== Starting Detection ==========")
	log.Printf("[ZScanDetector] Target: %s", target)
	log.Printf("[ZScanDetector] Configuration:")
	log.Printf("  - Config Path: %s", z.configPath)
	log.Printf("  - Templates Dir: %s", z.templatesDir)

	// 解析目标网段
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		log.Printf("[ZScanDetector] Failed to parse target CIDR %s: %v", target, err)
		return nil, err
	}
	log.Printf("[ZScanDetector] Parsed network range: %s", ipNet.String())

	// 初始化扫描器
	log.Printf("[ZScanDetector] Initializing scanner...")
	scanner, err := stage.NewScanner(
		z.configPath,
		z.templatesDir,
		false,
		false,
		"",
		"",
	)
	if err != nil {
		log.Printf("[ZScanDetector] Failed to initialize scanner: %v", err)
		return nil, err
	}
	defer scanner.Close()

	log.Printf("[ZScanDetector] Starting scan for network: %s", target)
	nodes, err := scanner.Scan(target)
	if err != nil {
		log.Printf("[ZScanDetector] Scan failed: %v", err)
		return nil, err
	}

	return nodes, nil
}
