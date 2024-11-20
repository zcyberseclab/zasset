package zasset

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

// SNMPDetector SNMP探测器
type SNMPDetector struct {
	BaseDetector
	community string
	version   gosnmp.SnmpVersion
}

// NewSNMPDetector 创建新的 SNMP 探测器，使用内置的社区字符串和 SNMP 版本
func NewSNMPDetector(timeout time.Duration) *SNMPDetector {
	return &SNMPDetector{
		BaseDetector: BaseDetector{timeout: timeout},
		community:    "public",         // 默认社区字符串
		version:      gosnmp.Version2c, // 默认 SNMP 版本
	}
}

func (s *SNMPDetector) Name() string {
	return "SNMPDetector"
}

func (s *SNMPDetector) sendSNMPRequests(ctx context.Context, ips []string) ([]stage.Node, error) {
	var wg sync.WaitGroup
	resultsChan := make(chan stage.Node, len(ips))
	results := make([]stage.Node, 0)
	workerCount := 10

	jobs := make(chan string, len(ips))

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if result := s.scanSNMP(ip); result != nil {
					resultsChan <- *result
				}
			}
		}()
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

func (s *SNMPDetector) scanSNMP(ip string) *stage.Node {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: s.community,
		Version:   s.version,
		Timeout:   s.timeout,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		return nil
	}
	defer snmp.Conn.Close()

	node := &stage.Node{
		IP: ip,
	}

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.5.0", // sysName
		".1.3.6.1.2.1.1.6.0", // sysLocation
		".1.3.6.1.2.1.1.4.0", // sysContact
	}

	pkt, err := snmp.Get(oids)
	if err != nil {
		return nil
	}

	for _, variable := range pkt.Variables {
		switch variable.Name {
		case ".1.3.6.1.2.1.1.1.0":
			sysDescr := string(variable.Value.([]byte))

			parseDeviceInfo(node, sysDescr)
		case ".1.3.6.1.2.1.1.5.0":
			node.Model = string(variable.Value.([]byte))
			//case ".1.3.6.1.2.1.1.6.0":
			//	node.Info["SysLocation"] = string(variable.Value.([]byte))
			//case ".1.3.6.1.2.1.1.4.0":
			//	node.Info["SysContact"] = string(variable.Value.([]byte))
		}
	}

	return node
}

func (s *SNMPDetector) Detect(target string) ([]stage.Node, error) {
	log.Printf("Starting detection for target: %s", target)

	targets, err := getIPsFromCIDR(target)
	if err != nil {
		return nil, err
	}

	// Create a context
	ctx := context.Background()

	nodes, err := s.sendSNMPRequests(ctx, targets)
	if err != nil {
		log.Printf("[SNMP] Error during detection: %v\n", err)
		return nil, err
	}

	log.Printf("[SNMP] Detection completed. Found %d nodes\n", len(nodes))
	for i := 0; i < len(nodes); i++ {
		log.Printf("[SNMP] Found node: %s\n", nodes[i].IP)
	}

	return nodes, err
}

func parseDeviceInfo(node *stage.Node, sysDescr string) {
	sysDescr = strings.ToLower(sysDescr)

	// 检测操作系统
	if strings.Contains(sysDescr, "windows") {
		node.OS = "windows"
	} else if strings.Contains(sysDescr, "linux") {
		node.OS = "linux"
	}

	// 检测设备类型和制造商
	switch {
	case strings.Contains(sysDescr, "cisco"):
		node.Devicetype = "router"
		node.Manufacturer = "cisco"
	case strings.Contains(sysDescr, "hp procurve"):
		node.Devicetype = "switch"
		node.Manufacturer = "hp"
	case strings.Contains(sysDescr, "juniper"):
		node.Devicetype = "router"
		node.Manufacturer = "juniper"
	case strings.Contains(sysDescr, "fortigate"):
		node.Devicetype = "firewall"
		node.Manufacturer = "fortinet"
	case strings.Contains(sysDescr, "mikrotik"):
		node.Devicetype = "router"
		node.Manufacturer = "mikrotik"
	case strings.Contains(sysDescr, "ubiquiti"):
		node.Devicetype = "network"
		node.Manufacturer = "ubiquiti"
	case strings.Contains(sysDescr, "printer"):
		node.Devicetype = "printer"
		if strings.Contains(sysDescr, "xerox") {
			node.Manufacturer = "xerox"
		} else if strings.Contains(sysDescr, "canon") {
			node.Manufacturer = "canon"
		} else if strings.Contains(sysDescr, "hp") {
			node.Manufacturer = "hp"
		} else if strings.Contains(sysDescr, "ricoh") {
			node.Manufacturer = "ricoh"
		}
	}
}
