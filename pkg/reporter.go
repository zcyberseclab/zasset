package zasset

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

// Reporter 接口定义了上报行为
type Reporter interface {
	Report(node *stage.Node) error
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
	initMutex             sync.Mutex  // 用于初始化过程的互斥锁
)

// InitMultiReporter 初始化MultiReporter，只能调用一次，重复调用会返回错误
func InitMultiReporter(config ReporterConfig) error {
	// 如果已经初始化过，直接返回错误
	if initialized.Load() {
		return fmt.Errorf("MultiReporter already initialized")
	}

	// 加锁确保并发安全
	initMutex.Lock()
	defer initMutex.Unlock()

	// 双重检查，防止在等待锁的过程中被其他协程初始化
	if initialized.Load() {
		return fmt.Errorf("MultiReporter already initialized")
	}

	once.Do(func() {
		mr := &MultiReporter{
			reporters: make([]Reporter, 0),
		}

		// 根据配置启用相应的reporter
		if config.EnableConsole {
			mr.AddReporter(&ConsoleReporter{})
		}

		if config.HTTPEndpoint != "" {
			httpReporter := NewHTTPReporter(config.HTTPEndpoint)
			mr.AddReporter(httpReporter)
		}

		if config.DBConfig != nil {
			db, err := sql.Open(config.DBConfig.Driver, config.DBConfig.DSN)
			if err != nil {
				initErr = fmt.Errorf("failed to connect to database: %w", err)
				return
			}
			if err := db.Ping(); err != nil {
				db.Close()
				initErr = fmt.Errorf("failed to ping database: %w", err)
				return
			}
			mr.AddReporter(NewDBReporter(db))
		}

		multiReporterInstance = mr
	})

	if initErr != nil {
		return initErr
	}

	// 设置初始化完成标志
	initialized.Store(true)
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

// ConsoleReporter 控制台上报器
type ConsoleReporter struct{}

func (cr *ConsoleReporter) Report(node *stage.Node) error {
	// 实现控制台输出，可以根据需要格式化输出
	fmt.Printf("Node Result: %+v\n", node)
	return nil
}

// DBReporter 数据库上报器
type DBReporter struct {
	db *sql.DB
}

func NewDBReporter(db *sql.DB) *DBReporter {
	return &DBReporter{db: db}
}

func (dr *DBReporter) Report(node *stage.Node) error {
	// TODO: 实现数据库存储逻辑
	// 根据 stage.Node 的结构设计相应的表结构和存储逻辑
	return nil
}

// HTTPReporter HTTP上报器
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

// ReporterConfig 定义上报器的配置参数
type ReporterConfig struct {
	EnableConsole bool      // 是否启用控制台输出
	HTTPEndpoint  string    // HTTP上报地址，非空则启用HTTP上报
	DBConfig      *DBConfig // 数据库配置，非空则启用数据库上报
}

// DBConfig 数据库配置
type DBConfig struct {
	Driver string // 数据库驱动类型
	DSN    string // 数据库连接字符串
}
