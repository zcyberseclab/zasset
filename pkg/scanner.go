package zasset

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type Scanner struct {
	config    *ScannerConfig
	detectors []Detector
}

type ScannerConfig struct {
	ConfigPath   string
	TemplatesDir string
	EnableGeo    bool
	EnableCensys bool
	CensysAPIKey string
	CensysSecret string
	Interface    string
	Timeout      time.Duration
}

func NewScanner(config *ScannerConfig) *Scanner {
	s := &Scanner{
		config: config,
		detectors: []Detector{
			NewZScanDetector(config),
			NewPassiveDetector(config.Interface),
			//NewARPDetector(config.Interface),
			NewPingDetector(config.Timeout),
			NewDCERPCDetector(config.Timeout),
			NewSNMPDetector(config.Timeout),
			NewCameraDetector(config.Timeout),
		},
	}
	return s
}

// StartScan 开始扫描，提供给前端调用
func (s *Scanner) StartScan(target string) error {
	log.Printf("====== Starting scan with %d detectors ======\n", len(s.detectors))
	log.Printf("Starting scan for target: %s\n", target)

	// 1. 创建扫描记录
	scanID, err := s.createScanRecord()
	if err != nil {
		log.Printf("Failed to create scan record: %v\n", err)
		return err
	}

	startTime := time.Now()

	// 使用 map 存储合并果，以 IP 为 key
	resultMap := make(map[string]*stage.Node)
	var resultMutex sync.RWMutex

	// 创建等待组和错误通道
	var wg sync.WaitGroup
	errChan := make(chan error, len(s.detectors))

	// 2. 并发执行所有探测器的扫描
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

				// 合并结果
				resultMutex.Lock()
				for _, node := range results {
					if existing, exists := resultMap[node.IP]; exists {
						// 合并节点信息
						mergeNodes(existing, &node)
					} else {
						// 创建新节点的副本
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

	// 检查是否有错误发生
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	// 将 map 转换为切片
	var allResults []stage.Node
	resultMutex.RLock()
	for _, node := range resultMap {
		allResults = append(allResults, *node)
	}
	resultMutex.RUnlock()

	log.Printf("====== Scan completed. Total unique results: %d ======\n", len(allResults))

	// 3. 保存扫描结果
	if len(allResults) > 0 {
		if err := s.saveResults(scanID, allResults); err != nil {
			log.Printf("Failed to save results: %v\n", err)
			s.updateScanStatus(scanID, "failed", int(time.Since(startTime).Seconds()))
			return err
		}
	} else {
		log.Printf("No results found for target: %s\n", target)
	}

	// 4. 更新扫描状态
	duration := int(time.Since(startTime).Seconds())
	if err := s.updateScanStatus(scanID, "completed", duration); err != nil {
		log.Printf("Failed to update scan status: %v\n", err)
		return err
	}

	log.Printf("Scan completed in %d seconds\n", duration)

	// 如果有错误，返回第一个错误
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// mergeNodes 合并两个节点的信息
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

// uniqueStrings 去除字符串切片中的重复项
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

// GetAssets 获取资产列表，提供给前端调用
func (s *Scanner) GetAssets() ([]map[string]interface{}, error) {
	lastScanTime, err := s.GetLastScanTime()
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(`
        SELECT 
            ip, domain, hostname, mac, os, manufacturer, devicetype,
            ports, sensitive_info, tags, ports_history, ports_history_desc,
            created_at, updated_at,
            CASE 
                WHEN (julianday(updated_at) - julianday(?)) * 86400 <= 6000 THEN 'online'
                ELSE 'offline'
            END as status
        FROM assets
        ORDER BY ip ASC`,
		lastScanTime)
	if err != nil {
		log.Printf("ERROR querying assets: %v\n", err)
		return []map[string]interface{}{}, err
	}
	defer rows.Close()

	assets := make([]map[string]interface{}, 0)
	rowCount := 0

	for rows.Next() {
		rowCount++
		var asset struct {
			IP               string
			Domain           sql.NullString
			Hostname         sql.NullString
			MAC              sql.NullString
			OS               sql.NullString
			Manufacturer     sql.NullString
			Devicetype       sql.NullString
			Ports            sql.NullString
			SensitiveInfo    sql.NullString
			Tags             sql.NullString
			PortsHistory     sql.NullString
			PortsHistoryDesc sql.NullString
			CreatedAt        time.Time
			UpdatedAt        time.Time
			Status           string
		}

		if err := rows.Scan(
			&asset.IP, &asset.Domain, &asset.Hostname, &asset.MAC,
			&asset.OS, &asset.Manufacturer, &asset.Devicetype,
			&asset.Ports, &asset.SensitiveInfo, &asset.Tags,
			&asset.PortsHistory, &asset.PortsHistoryDesc,
			&asset.CreatedAt, &asset.UpdatedAt,
			&asset.Status,
		); err != nil {
			log.Printf("ERROR scanning row %d: %v\n", rowCount, err)
			return nil, err
		}

		// 构建返回结果
		result := map[string]interface{}{
			"ip":         asset.IP,
			"created_at": asset.CreatedAt,
			"updated_at": asset.UpdatedAt,
			"status":     asset.Status,
		}

		// 处理可能为空的��段
		if asset.Domain.Valid {
			result["domain"] = asset.Domain.String
		}
		if asset.Hostname.Valid {
			result["hostname"] = asset.Hostname.String
		}
		if asset.MAC.Valid {
			result["mac"] = asset.MAC.String
		}
		if asset.OS.Valid {
			result["os"] = asset.OS.String
		}
		if asset.Manufacturer.Valid {
			result["manufacturer"] = asset.Manufacturer.String
		}
		if asset.Devicetype.Valid {
			result["devicetype"] = asset.Devicetype.String
		}

		// 处理JSON字段
		if asset.Ports.Valid {
			var ports interface{}
			if err := json.Unmarshal([]byte(asset.Ports.String), &ports); err == nil {
				result["ports"] = ports
			}
		}
		if asset.SensitiveInfo.Valid {
			var sensitiveInfo interface{}
			if err := json.Unmarshal([]byte(asset.SensitiveInfo.String), &sensitiveInfo); err == nil {
				result["sensitive_info"] = sensitiveInfo
			}
		}
		if asset.Tags.Valid {
			var tags interface{}
			if err := json.Unmarshal([]byte(asset.Tags.String), &tags); err == nil {
				result["tags"] = tags
			}
		}
		if asset.PortsHistory.Valid {
			var portsHistory interface{}
			if err := json.Unmarshal([]byte(asset.PortsHistory.String), &portsHistory); err == nil {
				result["ports_history"] = portsHistory
			}
		}
		if asset.PortsHistoryDesc.Valid {
			var portsHistoryDesc interface{}
			if err := json.Unmarshal([]byte(asset.PortsHistoryDesc.String), &portsHistoryDesc); err == nil {
				result["ports_history_desc"] = portsHistoryDesc
			}
		}

		//// 如果有端口数据，打印出来
		//if asset.Ports.Valid {
		//	log.Printf("Ports data for IP %s: %s\n", asset.IP, asset.Ports.String)
		//}

		assets = append(assets, result)
	}

	if err = rows.Err(); err != nil {
		log.Printf("ERROR during row iteration: %v\n", err)
		return []map[string]interface{}{}, err
	}

	return assets, nil
}

// GetLastScanTime 获取最后扫描时间，提供给前端调用
func (s *Scanner) GetLastScanTime() (time.Time, error) {
	var lastScan time.Time
	err := db.QueryRow(`
        SELECT scan_time FROM scan_records 
        WHERE status = 'completed' 
        ORDER BY scan_time DESC LIMIT 1
    `).Scan(&lastScan)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return lastScan, err
}

// 内部方法：创建扫描记录
func (s *Scanner) createScanRecord() (int64, error) {
	result, err := db.Exec(`
        INSERT INTO scan_records (scan_time, status)
        VALUES (?, ?)
    `, time.Now(), "running")
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// 内部方法：更新扫描状态
func (s *Scanner) updateScanStatus(scanID int64, status string, duration int) error {
	_, err := db.Exec(`
        UPDATE scan_records 
        SET status = ?, duration = ?
        WHERE id = ?
    `, status, duration, scanID)
	return err
}

// saveResults 保存扫描结果
func (s *Scanner) saveResults(scanID int64, results interface{}) error {

	nodes, ok := results.([]stage.Node)
	if !ok {
		log.Printf("ERROR: Invalid results type. Expected []stage.Node, got %T\n", results)
		return fmt.Errorf("invalid results type")
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("ERROR starting transaction: %v\n", err)
		return err
	}
	defer tx.Rollback()

	// 首先尝试更新现有记录
	updateStmt, err := tx.Prepare(`
        UPDATE assets SET 
            domain = COALESCE(?, domain),
            hostname = COALESCE(?, hostname),
            mac = COALESCE(?, mac),
            os = COALESCE(?, os),
            manufacturer = COALESCE(?, manufacturer),
            devicetype = COALESCE(?, devicetype),
            ports = COALESCE(?, ports),
            sensitive_info = COALESCE(?, sensitive_info),
            tags = COALESCE(?, tags),
            ports_history = COALESCE(?, ports_history),
            ports_history_desc = COALESCE(?, ports_history_desc),
            updated_at = DATETIME('now')
        WHERE ip = ?
    `)
	if err != nil {
		log.Printf("ERROR preparing update statement: %v\n", err)
		return err
	}
	defer updateStmt.Close()

	// 如果更新失败，则插入新记录
	insertStmt, err := tx.Prepare(`
        INSERT INTO assets (
            ip, domain, hostname, mac, os, manufacturer, devicetype,
            ports, sensitive_info, tags, ports_history, ports_history_desc,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `)
	if err != nil {
		log.Printf("ERROR preparing insert statement: %v\n", err)
		return err
	}
	defer insertStmt.Close()

	log.Printf("Processing %d nodes\n", len(nodes))

	for i, node := range nodes {

		portsJSON, err := json.Marshal(node.Ports)
		if err != nil {
			log.Printf("ERROR marshaling ports for node %d: %v\n", i, err)
			continue
		}
		sensitiveInfoJSON, err := json.Marshal(node.SensitiveInfo)
		if err != nil {
			log.Printf("ERROR marshaling sensitive_info for node %d: %v\n", i, err)
			continue
		}
		tagsJSON, err := json.Marshal(node.Tags)
		if err != nil {
			log.Printf("ERROR marshaling tags for node %d: %v\n", i, err)
			continue
		}
		portsHistoryJSON, err := json.Marshal(node.PortsHistory)
		if err != nil {
			log.Printf("ERROR marshaling ports_history for node %d: %v\n", i, err)
			continue
		}
		portsHistoryDescJSON, err := json.Marshal(node.PortsHistoryDesc)
		if err != nil {
			log.Printf("ERROR marshaling ports_history_desc for node %d: %v\n", i, err)
			continue
		}

		// 先尝试更新
		log.Printf("Attempting to update existing record for IP: %s\n", node.IP)
		result, err := updateStmt.Exec(
			node.Domain,
			node.Hostname,
			node.MAC,
			node.OS,
			node.Manufacturer,
			node.Devicetype,
			string(portsJSON),
			string(sensitiveInfoJSON),
			string(tagsJSON),
			string(portsHistoryJSON),
			string(portsHistoryDescJSON),
			node.IP,
		)
		if err != nil {
			log.Printf("ERROR updating node %d: %v\n", i, err)
			continue
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("ERROR getting rows affected for update of node %d: %v\n", i, err)
			continue
		}

		// 如果没有更新任何记录，则插入新记录
		if rowsAffected == 0 {
			log.Printf("No existing record found for IP: %s, attempting insert\n", node.IP)
			_, err = insertStmt.Exec(
				node.IP,
				node.Domain,
				node.Hostname,
				node.MAC,
				node.OS,
				node.Manufacturer,
				node.Devicetype,
				string(portsJSON),
				string(sensitiveInfoJSON),
				string(tagsJSON),
				string(portsHistoryJSON),
				string(portsHistoryDescJSON),
			)
			if err != nil {
				log.Printf("ERROR inserting node %d: %v\n", i, err)
				continue
			}
			log.Printf("Successfully inserted new record for IP: %s\n", node.IP)
		} else {
			log.Printf("Successfully updated existing record for IP: %s\n", node.IP)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("ERROR committing transaction: %v\n", err)
		return err
	}

	log.Printf("Successfully saved all results for scanID: %d\n", scanID)
	return nil
}

// 辅助函数：安全地获取字符串值
func getStringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", v)
}

// 添加启用/禁用探测器方法
func (s *Scanner) EnableDetector(name string, enabled bool) {
	for i, d := range s.detectors {
		if d.Name() == name {
			if !enabled {
				// 禁用探测器
				s.detectors = append(s.detectors[:i], s.detectors[i+1:]...)
			}
			return
		}
	}
}

// 添加获取可用探测器列表方法
func (s *Scanner) GetAvailableDetectors() []string {
	detectors := make([]string, len(s.detectors))
	for i, d := range s.detectors {
		detectors[i] = d.Name()
	}
	return detectors
}

// AssetStatistics 资产统计结构
type AssetStatistics struct {
	TotalAssets      int            `json:"total_assets"`
	OnlineAssets     int            `json:"online_assets"`
	OfflineAssets    int            `json:"offline_assets"`
	DeviceTypes      map[string]int `json:"device_types"`
	OperatingSystems map[string]int `json:"operating_systems"`
}

// GetAssetStatistics 获取资产统计信息
func (s *Scanner) GetAssetStatistics() (*AssetStatistics, error) {
	lastScanTime, err := s.GetLastScanTime()
	if err != nil {
		return nil, err
	}

	stats := &AssetStatistics{
		DeviceTypes:      make(map[string]int),
		OperatingSystems: make(map[string]int),
	}

	// 执行统计查询
	rows, err := db.Query(`
		WITH asset_status AS (
			SELECT 
				COUNT(*) as total,
				SUM(CASE 
					WHEN (julianday(updated_at) - julianday(?)) * 86400 <= 3600 THEN 1 
					ELSE 0 
				END) as online,
				SUM(CASE 
					WHEN (julianday(updated_at) - julianday(?)) * 86400 > 3600 THEN 1 
					ELSE 0 
				END) as offline
			FROM assets
		)
		SELECT total, online, offline FROM asset_status
	`, lastScanTime, lastScanTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&stats.TotalAssets, &stats.OnlineAssets, &stats.OfflineAssets)
		if err != nil {
			return nil, err
		}
	}

	// 统计设备类型
	deviceRows, err := db.Query(`
		SELECT 
			COALESCE(devicetype, 'Unknown') as device_type,
			COUNT(*) as count
		FROM assets
		GROUP BY devicetype
	`)
	if err != nil {
		return nil, err
	}
	defer deviceRows.Close()

	for deviceRows.Next() {
		var deviceType string
		var count int
		if err := deviceRows.Scan(&deviceType, &count); err != nil {
			return nil, err
		}
		if deviceType == "" {
			deviceType = "Unknown"
		}
		stats.DeviceTypes[deviceType] = count
	}

	// 统计操作系统
	osRows, err := db.Query(`
		SELECT 
			COALESCE(os, 'Unknown') as os,
			COUNT(*) as count
		FROM assets
		GROUP BY os
	`)
	if err != nil {
		return nil, err
	}
	defer osRows.Close()

	for osRows.Next() {
		var os string
		var count int
		if err := osRows.Scan(&os, &count); err != nil {
			return nil, err
		}
		if os == "" {
			os = "Unknown"
		}
		stats.OperatingSystems[os] = count
	}

	return stats, nil
}

// DeleteAsset 删除资产记录
func (s *Scanner) DeleteAsset(ip string) error {
	log.Printf("Deleting asset with IP: %s\n", ip)

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		log.Printf("ERROR starting transaction: %v\n", err)
		return fmt.Errorf("failed to start transaction: %v", err)
	}
	defer tx.Rollback()

	// 删除资产记录
	result, err := tx.Exec(`
		DELETE FROM assets 
		WHERE ip = ?
	`, ip)
	if err != nil {
		log.Printf("ERROR deleting asset: %v\n", err)
		return fmt.Errorf("failed to delete asset: %v", err)
	}

	// 检查是否有记录被删除
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("ERROR checking rows affected: %v\n", err)
		return fmt.Errorf("failed to check rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no asset found with IP: %s", ip)
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		log.Printf("ERROR committing transaction: %v\n", err)
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("Successfully deleted asset with IP: %s\n", ip)
	return nil
}

// DeleteAllAssets 删除所有资产
func (s *Scanner) DeleteAllAssets() error {
	_, err := db.Exec(`
		DELETE FROM assets
	`)
	return err
}
