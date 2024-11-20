package zasset

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

// Detector 探测器接口
type Detector interface {
	Detect(target string) ([]stage.Node, error)
	Name() string
}

// BaseDetector 基础探测器结构，包含共同的字段
type BaseDetector struct {
	timeout time.Duration
}

// ServiceInfoToString 将 ServiceInfo 数组转换为端口字符串
func ServiceInfoToString(ports []*stage.ServiceInfo) string {
	var portStrings []string
	for _, port := range ports {
		portStrings = append(portStrings, fmt.Sprintf("%d", port.Port))
	}
	return strings.Join(portStrings, ",")
}

// PortHistory 端口历史记录结构体
type PortHistory struct {
	Ports     string    `json:"ports"`
	Desc      string    `json:"desc"`
	Timestamp time.Time `json:"timestamp"`
}

// SaveAsset 保存或更新资产信息
func SaveAsset(db *sql.DB, node *stage.Node) error {
	log.Printf("开始保存资产信息: IP=%s, Hostname=%s, MAC=%s\n", node.IP, node.Hostname, node.MAC)

	// 检查IP是否存在
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM assets WHERE ip = ?)", node.IP).Scan(&exists)
	if err != nil {
		log.Printf("检查IP存在时出错: IP=%s, Error=%v\n", node.IP, err)
		return fmt.Errorf("检查IP存在时出错: %v", err)
	}
	log.Printf("IP检查结果: IP=%s, Exists=%v\n", node.IP, exists)

	// 将 ServiceInfo 转换为端口字符串
	portsStr := ServiceInfoToString(node.Ports)
	log.Printf("端口信息: IP=%s, Ports=%s\n", node.IP, portsStr)

	if exists {
		var currentPorts string
		var currentPortHistory string
		err := db.QueryRow("SELECT ports, port_history FROM assets WHERE ip = ?", node.IP).Scan(&currentPorts, &currentPortHistory)
		if err != nil {
			log.Printf("获取当前端口数据时出错: IP=%s, Error=%v\n", node.IP, err)
			return fmt.Errorf("获取当前端口数据时出错: %v", err)
		}
		log.Printf("当前数据库中的端口: IP=%s, CurrentPorts=%s\n", node.IP, currentPorts)

		// 如果端口有变化，更新历史记录
		if currentPorts != portsStr {
			log.Printf("端口发生变化: IP=%s, OldPorts=%s, NewPorts=%s\n", node.IP, currentPorts, portsStr)

			// 解析现有的历史记录
			var portHistories []PortHistory
			if currentPortHistory != "" {
				if err := json.Unmarshal([]byte(currentPortHistory), &portHistories); err != nil {
					log.Printf("解析历史记录时出错: IP=%s, Error=%v\n", node.IP, err)
					return fmt.Errorf("解析历史记录时出错: %v", err)
				}
			}

			// 添加新的历史记录
			desc := AnalyzePortChanges(currentPorts, portsStr)
			newHistory := PortHistory{
				Ports:     currentPorts,
				Desc:      desc,
				Timestamp: time.Now(),
			}
			portHistories = append(portHistories, newHistory)

			// 转换回JSON
			historyJSON, err := json.Marshal(portHistories)
			if err != nil {
				log.Printf("转换历史记录为JSON时出错: IP=%s, Error=%v\n", node.IP, err)
				return fmt.Errorf("转换历史记录为JSON时出错: %v", err)
			}

			log.Printf("准备更新资产信息: IP=%s, NewPorts=%s\n", node.IP, portsStr)
			// 更新资产信息，包含历史记录
			result, err := db.Exec(`
				UPDATE assets 
				SET ports = ?, 
					hostname = ?,
					mac = ?,
					manufacturer = ?,
					domain = ?,
					tags = ?,
					devicetype = ?,
					port_history = ?,
					ports_history_desc = ?,
					updated_at = datetime('now')
				WHERE ip = ?`, portsStr, node.Hostname, node.MAC, node.Manufacturer,
				node.Domain, node.Tags, node.Devicetype,
				string(historyJSON), desc, node.IP)
			if err != nil {
				log.Printf("更新资产信息时出错: IP=%s, Error=%v\n", node.IP, err)
				return fmt.Errorf("更新资产信息时出错: %v", err)
			}
			rows, _ := result.RowsAffected()
			log.Printf("资产信息更新成功: IP=%s, AffectedRows=%d\n", node.IP, rows)
		}
	} else {
		log.Printf("准备插入新记录: IP=%s\n", node.IP)
		// 创建初始历史记录
		initialHistory := []PortHistory{{
			Ports:     portsStr,
			Desc:      "初始端口扫描",
			Timestamp: time.Now(),
		}}
		historyJSON, err := json.Marshal(initialHistory)
		if err != nil {
			log.Printf("创建初始历史记录时出错: IP=%s, Error=%v\n", node.IP, err)
			return fmt.Errorf("创建初始历史记录时出错: %v", err)
		}

		// IP不存在，执行插入
		result, err := db.Exec(`
			INSERT INTO assets (
				ip, ports, hostname, mac, manufacturer, 
				domain, tags, devicetype, port_history, ports_history_desc,
				created_at, updated_at
			) VALUES (
				?, ?, ?, ?, ?, 
				?, ?, ?, ?, ?,
				datetime('now'), datetime('now')
			)`, node.IP, portsStr, node.Hostname, node.MAC, node.Manufacturer,
			node.Domain, node.Tags, node.Devicetype,
			string(historyJSON), "初始端口扫描")
		if err != nil {
			log.Printf("插入新记录时出错: IP=%s, Error=%v\n", node.IP, err)
			return fmt.Errorf("插入新记录时出错: %v", err)
		}
		rows, _ := result.RowsAffected()
		log.Printf("新记录插入成功: IP=%s, AffectedRows=%d\n", node.IP, rows)
	}

	return nil
}

// AnalyzePortChanges 分析端口变化并生成描述
func AnalyzePortChanges(oldPorts, newPorts string) string {
	if oldPorts == "" {
		return "初始端口扫描"
	}

	oldPortSet := make(map[string]bool)
	newPortSet := make(map[string]bool)

	// 转换旧端口到集合
	for _, port := range strings.Split(oldPorts, ",") {
		if port = strings.TrimSpace(port); port != "" {
			oldPortSet[port] = true
		}
	}

	// 转换新端口到集合
	for _, port := range strings.Split(newPorts, ",") {
		if port = strings.TrimSpace(port); port != "" {
			newPortSet[port] = true
		}
	}

	// 分析变化
	var added, removed []string
	for port := range newPortSet {
		if !oldPortSet[port] {
			added = append(added, port)
		}
	}
	for port := range oldPortSet {
		if !newPortSet[port] {
			removed = append(removed, port)
		}
	}

	// 生成描述
	var changes []string
	if len(added) > 0 {
		sort.Strings(added)
		changes = append(changes, fmt.Sprintf("新增端口: %s", strings.Join(added, ",")))
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		changes = append(changes, fmt.Sprintf("关闭端口: %s", strings.Join(removed, ",")))
	}

	return strings.Join(changes, "; ")
}
