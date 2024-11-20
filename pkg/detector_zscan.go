package zasset

import (
	"log"

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
	log.Printf("[ZScan] Starting detection for target: %s\n", target)

	scanner, err := stage.NewScanner(
		z.configPath,
		z.templatesDir,
		false,
		false,
		"",
		"",
	)
	if err != nil {
		log.Printf("[ZScan] Failed to initialize scanner: %v\n", err)
		return nil, err
	}
	defer scanner.Close()

	// 执行扫描
	nodes, err := scanner.Scan(target)
	if err != nil {
		log.Printf("[ZScan] Scan failed: %v\n", err)
		return nil, err
	}

	log.Printf("[ZScan] Found %d nodes for target: %s\n", len(nodes), target)
	return nodes, nil
}
