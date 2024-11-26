package zasset

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type ScannerType int

const (
	ActiveScanner ScannerType = iota
	PassiveScanner
)

type ScannerConfig struct {
	ConfigPath     string
	TemplatesDir   string
	PassiveTimeout int
	NetworkCard    string
	Targets        []string
	ScannerType    ScannerType
}

type Scanner struct {
	config          *ScannerConfig
	detectors       []Detector
	stopChan        chan struct{}
	wg              sync.WaitGroup
	discoveredHosts int32
}

func NewScanner(config *ScannerConfig) *Scanner {
	s := &Scanner{
		config:   config,
		stopChan: make(chan struct{}),
	}

	if config.ScannerType == ActiveScanner {
		s.detectors = []Detector{
			NewZScanDetector(config),
			NewPingDetector(),
			NewDCERPCDetector(),
			NewSNMPDetector(),
			NewCameraDetector(),
		}
	} else {
		s.detectors = []Detector{
			NewPassiveDetector(),
		}
	}

	return s
}

// Start is the unified entry point for both active and passive scanning
func (s *Scanner) Start(targets []string) ([]stage.Node, error) {
	if s.config.ScannerType == ActiveScanner {
		return s.startActiveScan(targets)
	}
	return s.startPassiveScan()
}

// startActiveScan handles active scanning
func (s *Scanner) startActiveScan(targets []string) ([]stage.Node, error) {
	s.wg.Add(1)
	defer s.wg.Done()

	log.Printf("[Scanner] Starting active scan for targets: %v", targets)

	if len(s.detectors) == 0 {
		return nil, fmt.Errorf("no detectors initialized")
	}

	var allNodes []stage.Node
	nodeMap := make(map[string]*stage.Node)
	var nodesMutex sync.Mutex

	targetWg := sync.WaitGroup{}
	maxConcurrent := runtime.GOMAXPROCS(0) * 2
	semaphore := make(chan struct{}, maxConcurrent)

	maxDetectorConcurrent := 5
	detectorSemaphore := make(chan struct{}, maxDetectorConcurrent)

	timeouts := map[string]time.Duration{
		"SNMPDetector":   15 * time.Second,
		"ZScanDetector":  60 * time.Second,
		"PingDetector":   20 * time.Second,
		"DCERPCDetector": 5 * time.Second,
		"CameraDetector": 5 * time.Second,
	}

	for _, target := range targets {
		select {
		case <-s.stopChan:
			log.Printf("[Scanner] Scan stopped before processing target: %s", target)
			return allNodes, nil
		default:
		}

		targetWg.Add(1)
		go func(target string) {
			defer targetWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			log.Printf("[Scanner] Actively scanning target: %s", target)

			var detectorWg sync.WaitGroup
			detectorWg.Add(len(s.detectors))

			for _, detector := range s.detectors {
				go func(d Detector, t string) {
					defer detectorWg.Done()

					detectorName := d.Name()
					log.Printf("[Scanner] Starting detector %s for target %s", detectorName, t)

					done := make(chan bool)
					var nodes []stage.Node
					var err error

					go func() {
						detectorSemaphore <- struct{}{}
						nodes, err = d.Detect(t)
						done <- true
					}()

					timeout := timeouts[detectorName]
					select {
					case <-done:
						if err != nil {
							log.Printf("[Scanner] Detector %s failed for target %s: %v", detectorName, t, err)
							return
						}
					case <-time.After(timeout):
						log.Printf("[Scanner] Detector %s timed out for target %s", detectorName, t)
						return
					}

					if len(nodes) > 0 {
						log.Printf("[Scanner] Detector %s found %d nodes for target %s", detectorName, len(nodes), t)
						s.incrementDiscoveredHosts(len(nodes))

						nodesMutex.Lock()

						for _, node := range nodes {
							if existing, exists := nodeMap[node.IP]; exists {
								MergeNodes(existing, &node)
							} else {
								nodeCopy := node
								nodeMap[node.IP] = &nodeCopy
							}
						}
						nodesMutex.Unlock()
					} else {
						log.Printf("[Scanner] Detector %s found no nodes for target %s", detectorName, t)
					}

					<-detectorSemaphore
				}(detector, target)
			}

			detectorWg.Wait()
		}(target)
	}

	targetWg.Wait()

	reporter, err := GetMultiReporter()
	if err != nil {
		log.Printf("[Scanner] Warning: Failed to get reporter: %v", err)
	} else {
		var nodesToReport []*stage.Node
		for _, node := range nodeMap {
			nodesToReport = append(nodesToReport, node)
		}
		if err := reporter.ReportNodes(nodesToReport); err != nil {
			log.Printf("[Scanner] Warning: Failed to report nodes: %v", err)
		}
	}

	for _, node := range nodeMap {
		allNodes = append(allNodes, *node)
	}

	return allNodes, nil
}

// startPassiveScan handles passive scanning
func (s *Scanner) startPassiveScan() ([]stage.Node, error) {
	s.wg.Add(1)
	defer s.wg.Done()

	log.Printf("[Scanner] Starting passive scan")

	if len(s.detectors) == 0 {
		return nil, fmt.Errorf("no detectors initialized")
	}

	var allNodes []stage.Node
	nodeMap := make(map[string]*stage.Node) // 使用 map 来存储和合并节点
	var nodesMutex sync.Mutex
	var detectorWg sync.WaitGroup

	detectorWg.Add(len(s.detectors))

	// 并行执行所有passive detector
	for _, detector := range s.detectors {
		go func(d Detector) {
			defer detectorWg.Done()

			nodes, err := d.Detect("")
			if err != nil {
				log.Printf("[Scanner] Passive detector %s failed: %v", d.Name(), err)
				return
			}

			if len(nodes) > 0 {
				nodesMutex.Lock()
				for _, node := range nodes {
					if existing, exists := nodeMap[node.IP]; exists {
						MergeNodes(existing, &node)
					} else {
						nodeCopy := node
						nodeMap[node.IP] = &nodeCopy
					}
				}
				nodesMutex.Unlock()
			}
		}(detector)
	}

	detectorWg.Wait()

	reporter, err := GetMultiReporter()
	if err != nil {
		log.Printf("[Scanner] Warning: Failed to get reporter: %v", err)
	} else {
		var nodesToReport []*stage.Node
		for _, node := range nodeMap {
			nodesToReport = append(nodesToReport, node)
		}
		if err := reporter.ReportNodes(nodesToReport); err != nil {
			log.Printf("[Scanner] Warning: Failed to report nodes: %v", err)
		}
	}

	for _, node := range nodeMap {
		allNodes = append(allNodes, *node)
	}

	return allNodes, nil
}

func (s *Scanner) Stop() {
	close(s.stopChan)
	s.wg.Wait()

	for _, detector := range s.detectors {
		if closer, ok := detector.(interface{ Close() }); ok {
			closer.Close()
		}
	}

	log.Printf("Scanner stopped successfully")
}

func MergeNodes(existing *stage.Node, new *stage.Node) {
	// 合并端口信息
	for _, newPort := range new.Ports {
		portExists := false
		for _, existingPort := range existing.Ports {
			if newPort == existingPort {
				portExists = true
				break
			}
		}
		if !portExists {
			existing.Ports = append(existing.Ports, newPort)
		}
	}

	// 合并主机名（如果新的非空）
	if new.Hostname != "" {
		existing.Hostname = new.Hostname
	}

	// 合并操作系统信息（如果新的非空）
	if new.OS != "" {
		existing.OS = new.OS
	}

	// 合并设备类型（如果新的非空）
	if new.Devicetype != "" {
		existing.Devicetype = new.Devicetype
	}

	// 合并标签
	for _, newTag := range new.Tags {
		tagExists := false
		for _, existingTag := range existing.Tags {
			if newTag == existingTag {
				tagExists = true
				break
			}
		}
		if !tagExists {
			existing.Tags = append(existing.Tags, newTag)
		}
	}
}

func (s *Scanner) incrementDiscoveredHosts(count int) {
	atomic.AddInt32(&s.discoveredHosts, int32(count))
}

func (s *Scanner) GetDiscoveredHosts() int {
	return int(atomic.LoadInt32(&s.discoveredHosts))
}
