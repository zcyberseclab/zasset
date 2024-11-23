package zasset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/zcyberseclab/zscan/pkg/stage"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Reporter 接口定义上报行为
type Reporter interface {
	Report(data *stage.Node) error
	Close() error
}

// HTTPReporter HTTP上报实现
type HTTPReporter struct {
	url string
}

func (r *HTTPReporter) Report(data *stage.Node) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := http.Post(r.url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (r *HTTPReporter) Close() error {
	return nil
}

// DBReporter 数据库上报实现
type DBReporter struct {
	db *gorm.DB
}

func (r *DBReporter) Report(data *stage.Node) error {
	return r.db.Create(data).Error
}

func (r *DBReporter) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ConsoleReporter 控制台输出实现
type ConsoleReporter struct{}

func (r *ConsoleReporter) Report(data *stage.Node) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	println(string(jsonData))
	return nil
}

func (r *ConsoleReporter) Close() error {
	return nil
}

// 初始化数据库连接
func initDB(dbType, dsn string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch dbType {
	case "sqlite":
		if dsn == "" {
			dsn = "asset.db"
		}
		dialector = sqlite.Open(dsn)

	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// 自动迁移表结构
	err = db.AutoMigrate(&stage.Node{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// NewReporter 创建reporter实例
func NewReporter(reportType string, config ReporterConfig) (Reporter, error) {
	switch reportType {
	case "http":
		if config.URL == "" {
			return nil, fmt.Errorf("HTTP reporter requires URL")
		}
		return &HTTPReporter{url: config.URL}, nil
	case "db":
		if config.DBType == "" {
			config.DBType = "sqlite"
		}
		db, err := initDB(config.DBType, config.DBDSN)
		if err != nil {
			return nil, err
		}
		return &DBReporter{db: db}, nil
	default:
		return &ConsoleReporter{}, nil
	}
}

// ReporterConfig 配置结构
type ReporterConfig struct {
	URL    string // HTTP上报URL
	DBType string // 数据库类型：sqlite(默认), mysql, postgres
	DBDSN  string // 数据库连接字符串
}
