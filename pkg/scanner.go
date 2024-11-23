package zasset

import (
	"fmt"
	"log"
	"sync"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type Scanner struct {
	config    *ScannerConfig
	detectors []Detector
	reporter  Reporter
}

type ScannerConfig struct {
	ConfigPath   string
	TemplatesDir string
	ReportURL    string
	DBType       string
	DBDSN        string
}

func NewScanner(config *ScannerConfig) *Scanner {
	s := &Scanner{
		config: config,
		detectors: []Detector{
			NewZScanDetector(config),
			NewPassiveDetector(),
			NewPingDetector(),
			NewDCERPCDetector(),
			NewSNMPDetector(),
			NewCameraDetector(),
		},
	}

	reporterConfig := &ReporterConfig{
		URL:    config.ReportURL,
		DBType: config.DBType,
		DBDSN:  config.DBDSN,
	}

	var reportType string
	switch {
	case config.ReportURL != "":
		reportType = "http"
	case config.DBType != "" || config.DBDSN != "":
		reportType = "db"
	default:
		reportType = "console"
	}

	reporter, err := NewReporter(reportType, *reporterConfig)
	if err != nil {
		log.Printf("Failed to initialize reporter: %v", err)
	} else {
		s.reporter = reporter
	}

	return s
}

func (s *Scanner) StartScan(target string) ([]stage.Node, error) {

	resultMap := make(map[string]*stage.Node)
	var resultMutex sync.RWMutex

	var wg sync.WaitGroup
	errChan := make(chan error, len(s.detectors))

	for _, detector := range s.detectors {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()

			results, err := d.Detect(target)
			if err != nil {
				log.Printf("Detector %s failed: %v\n", d.Name(), err)
				errChan <- fmt.Errorf("detector %s failed: %v", d.Name(), err)
				return
			}

			if results != nil {
				log.Printf("Detector %s found %d results\n", d.Name(), len(results))

				resultMutex.Lock()
				for _, node := range results {
					if existing, exists := resultMap[node.IP]; exists {

						mergeNodes(existing, &node)
					} else {

						nodeCopy := node
						resultMap[node.IP] = &nodeCopy
					}
				}
				resultMutex.Unlock()
			} else {
				log.Printf("Detector %s returned no results\n", d.Name())
			}
		}(detector)
	}

	// 等待所有探测器完成
	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	var allResults []stage.Node
	resultMutex.RLock()
	for _, node := range resultMap {
		allResults = append(allResults, *node)
	}
	resultMutex.RUnlock()

	log.Printf("====== Scan completed. Total unique results: %d ======\n", len(allResults))

	if s.reporter != nil && len(allResults) > 0 {
		if err := s.reporter.Report(&allResults[0]); err != nil {
			log.Printf("Failed to report results: %v\n", err)
		}
	}

	if len(allResults) > 0 {
		return allResults, nil
	} else {
		log.Printf("No results found for target: %s\n", target)
		return nil, nil
	}

}

func mergeNodes(existing *stage.Node, new *stage.Node) {
	// 只更新非空字段
	if new.Hostname != "" {
		existing.Hostname = new.Hostname
	}
	if new.MAC != "" {
		existing.MAC = new.MAC
	}
	if new.OS != "" {
		existing.OS = new.OS
	}
	if new.Manufacturer != "" {
		existing.Manufacturer = new.Manufacturer
	}
	if new.Domain != "" {
		existing.Domain = new.Domain
	}
	if new.Devicetype != "" {
		existing.Devicetype = new.Devicetype
	}

	// 合并端口信息
	if len(new.Ports) > 0 {
		if existing.Ports == nil {
			existing.Ports = []*stage.ServiceInfo{}
		}
		// 合并端口，避免重复
		portMap := make(map[int]bool)
		for _, port := range existing.Ports {
			portMap[port.Port] = true
		}
		for _, port := range new.Ports {
			if !portMap[port.Port] {
				existing.Ports = append(existing.Ports, port)
			}
		}
	}

	// 合并敏感信息
	if len(new.SensitiveInfo) > 0 {
		if existing.SensitiveInfo == nil {
			existing.SensitiveInfo = []string{}
		}
		// 合并敏感信息，避免重复
		infoMap := make(map[string]bool)
		for _, info := range existing.SensitiveInfo {
			infoMap[info] = true
		}
		for _, info := range new.SensitiveInfo {
			if !infoMap[info] {
				existing.SensitiveInfo = append(existing.SensitiveInfo, info)
			}
		}
	}

	// 合并标签
	if len(new.Tags) > 0 {
		if existing.Tags == nil {
			existing.Tags = make([]string, 0)
		}
		existing.Tags = append(existing.Tags, new.Tags...)
		// 去重
		existing.Tags = uniqueStrings(existing.Tags)
	}
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, str := range slice {
		if _, exists := seen[str]; !exists {
			seen[str] = struct{}{}
			result = append(result, str)
		}
	}
	return result
}
