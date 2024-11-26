package zasset

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

// Reporter 接口定义了上报行为
type Reporter interface {
	Report(node *stage.Node) error
	ReportNodes(nodes []*stage.Node) error
}

// MultiReporter 支持多种上报方式
type MultiReporter struct {
	reporters []Reporter
}

var (
	multiReporterInstance *MultiReporter
	once                  sync.Once
	initErr               error
	initialized           atomic.Bool // 使用原子操作的布尔值来标记初始化状态
)

func InitMultiReporter(config *ReporterConfig) error {
	once.Do(func() {
		if config == nil {
			initErr = fmt.Errorf("config cannot be nil")
			return
		}

		reporters := make([]Reporter, 0)

		// 如果启用了控制台输出
		if config.EnableConsole {
			reporters = append(reporters, &ConsoleReporter{})
		}

		// 如果配置了HTTP端点
		if config.HTTPEndpoint != "" {
			httpReporter := NewHTTPReporter(config.HTTPEndpoint)
			reporters = append(reporters, httpReporter)
		}

		// 如果配置了数据库连接信息
		if config.Driver != "" && config.DSN != "" {
			db, err := sql.Open(config.Driver, config.DSN)
			if err != nil {
				initErr = fmt.Errorf("failed to open database connection: %v", err)
				return
			}
			reporters = append(reporters, NewDBReporter(db))
		}

		if len(reporters) == 0 {
			initErr = fmt.Errorf("no reporters configured")
			return
		}

		multiReporterInstance = &MultiReporter{
			reporters: reporters,
		}
		initialized.Store(true)
	})

	if initErr != nil {
		return initErr
	}
	return nil
}

// GetMultiReporter 获取MultiReporter实例
func GetMultiReporter() (*MultiReporter, error) {
	if !initialized.Load() {
		return nil, fmt.Errorf("MultiReporter not initialized, please call InitMultiReporter first")
	}
	return multiReporterInstance, nil
}

func (mr *MultiReporter) AddReporter(r Reporter) {
	mr.reporters = append(mr.reporters, r)
}

func (mr *MultiReporter) Report(node *stage.Node) error {
	var errs []error
	for _, r := range mr.reporters {
		if err := r.Report(node); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("reporting errors: %v", errs)
	}
	return nil
}

// ReportNodes reports multiple nodes at once
func (mr *MultiReporter) ReportNodes(nodes []*stage.Node) error {
	var errs []error
	for _, r := range mr.reporters {
		if err := r.ReportNodes(nodes); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("reporting errors: %v", errs)
	}
	return nil
}

type ConsoleReporter struct{}

func (cr *ConsoleReporter) Report(node *stage.Node) error {
	fmt.Printf("\n=== Node Report ===\n")

	// Basic Information
	fmt.Printf("IP: %s\n", node.IP)
	if node.Domain != "" {
		fmt.Printf("Domain: %s\n", node.Domain)
	}
	if node.MAC != "" {
		fmt.Printf("MAC: %s\n", node.MAC)
	}
	if node.Hostname != "" {
		fmt.Printf("Hostname: %s\n", node.Hostname)
	}
	if len(node.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(node.Tags, ", "))
	}
	if node.OS != "" {
		fmt.Printf("OS: %s\n", node.OS)
	}

	// Ports and Vulnerabilities Summary
	if len(node.Ports) > 0 {
		fmt.Printf("Open Ports: %d\n", len(node.Ports))
	}
	if len(node.Vulnerabilities) > 0 {
		fmt.Printf("Vulnerabilities Found: %d\n", len(node.Vulnerabilities))
	}

	// Device Information
	if node.Manufacturer != "" {
		fmt.Printf("Manufacturer: %s\n", node.Manufacturer)
	}
	if node.Devicetype != "" {
		fmt.Printf("Device Type: %s\n", node.Devicetype)
	}
	if node.Model != "" {
		fmt.Printf("Model: %s\n", node.Model)
	}

	// Geographic Information (if available)
	if node.Country != "" {
		fmt.Printf("\nLocation: ")
		if node.City != "" {
			fmt.Printf("%s, ", node.City)
		}
		fmt.Printf("%s", node.Country)
		if node.CountryCode != "" {
			fmt.Printf(" (%s)", node.CountryCode)
		}
		fmt.Printf("\n")
	}

	// Network Information
	if node.ISP != "" {
		fmt.Printf("ISP: %s\n", node.ISP)
	}
	if node.NetworkType != "" {
		fmt.Printf("Network Type: %s\n", node.NetworkType)
	}

	// Security Information
	if node.IsAnonymous || node.IsAnonymousVPN || node.IsHosting || node.IsProxy || node.IsTorExitNode {
		fmt.Printf("\nSecurity Flags:\n")
		if node.IsAnonymous {
			fmt.Printf("- Anonymous\n")
		}
		if node.IsAnonymousVPN {
			fmt.Printf("- Anonymous VPN\n")
		}
		if node.IsHosting {
			fmt.Printf("- Hosting\n")
		}
		if node.IsProxy {
			fmt.Printf("- Proxy\n")
		}
		if node.IsTorExitNode {
			fmt.Printf("- Tor Exit Node\n")
		}
	}

	fmt.Printf("================\n")
	return nil
}

func (cr *ConsoleReporter) ReportNodes(nodes []*stage.Node) error {
	fmt.Printf("\n=== Batch Node Report (%d nodes) ===\n", len(nodes))
	for i, node := range nodes {
		fmt.Printf("\n[Node %d/%d]\n", i+1, len(nodes))
		if err := cr.Report(node); err != nil {
			log.Printf("Failed to report node: %v", err)
		}
	}
	fmt.Printf("=== End of Batch Report ===\n\n")
	return nil
}

type DBReporter struct {
	db *sql.DB
}

func NewDBReporter(db *sql.DB) *DBReporter {
	return &DBReporter{db: db}
}

func (dr *DBReporter) Report(node *stage.Node) error {
	return nil
}

func (dr *DBReporter) ReportNodes(nodes []*stage.Node) error {
	tx, err := dr.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

type HTTPReporter struct {
	endpoint string
	client   *http.Client
}

func NewHTTPReporter(endpoint string) *HTTPReporter {
	return &HTTPReporter{
		endpoint: endpoint,
		client:   &http.Client{},
	}
}

func (hr *HTTPReporter) Report(node *stage.Node) error {
	data, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("marshal node failed: %w", err)
	}

	resp, err := hr.client.Post(hr.endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (hr *HTTPReporter) ReportNodes(nodes []*stage.Node) error {
	data, err := json.Marshal(nodes)
	if err != nil {
		return fmt.Errorf("marshal nodes failed: %w", err)
	}

	resp, err := hr.client.Post(hr.endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

type ReporterConfig struct {
	EnableConsole bool
	HTTPEndpoint  string
	Driver        string
	DSN           string
}
