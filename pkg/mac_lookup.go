package zasset

import (
	"bufio"
	"compress/gzip"
	"embed"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var ouiData embed.FS

const (
	localDataDir  = "data"
	localDataFile = "oui.txt"
	embeddedFile  = "data/oui.txt.gz"
)

// OUIDatabase MAC地址前缀数据库
type OUIDatabase struct {
	manufacturers map[string]string
	mu            sync.RWMutex
	initialized   bool
}

var (
	ouiDB     *OUIDatabase
	ouiDBOnce sync.Once
)

// extractEmbeddedData 解压嵌入的数据到本地文件
func extractEmbeddedData() error {
	// 确保目录存在
	if err := os.MkdirAll(localDataDir, 0755); err != nil {
		return err
	}

	localPath := filepath.Join(localDataDir, localDataFile)

	// 如果本地文件已存在，直接返回
	if _, err := os.Stat(localPath); err == nil {
		log.Printf("[MAC] Using existing local database: %s\n", localPath)
		return nil
	}

	// 打开嵌入的压缩文件
	compressedFile, err := ouiData.Open(embeddedFile)
	if err != nil {
		return err
	}
	defer compressedFile.Close()

	// 创建gzip reader
	gzReader, err := gzip.NewReader(compressedFile)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	// 创建本地文件
	outFile, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// 解压数据到本地文件
	log.Printf("[MAC] Extracting database to: %s\n", localPath)
	_, err = io.Copy(outFile, gzReader)
	return err
}

// GetOUIDatabase 获取OUI数据库单例
func GetOUIDatabase() *OUIDatabase {
	ouiDBOnce.Do(func() {
		ouiDB = &OUIDatabase{
			manufacturers: make(map[string]string),
		}
		ouiDB.loadDatabase()
	})
	return ouiDB
}

// loadDatabase 加载OUI数据库
func (db *OUIDatabase) loadDatabase() {
	log.Println("[MAC] Loading OUI database...")

	// 首先尝试解压嵌入的数据
	if err := extractEmbeddedData(); err != nil {
		log.Printf("[MAC] Failed to extract embedded data: %v\n", err)
		return
	}

	// 打开本地数据文件
	localPath := filepath.Join(localDataDir, localDataFile)
	file, err := os.Open(localPath)
	if err != nil {
		log.Printf("[MAC] Failed to open local database: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	db.mu.Lock()
	defer db.mu.Unlock()

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}

		oui := strings.ReplaceAll(parts[0], "-", "")
		manufacturer := strings.TrimSpace(parts[1])
		manufacturer = strings.TrimPrefix(manufacturer, "(hex)\t")

		db.manufacturers[oui] = manufacturer
		count++
	}

	db.initialized = true
	log.Printf("[MAC] Loaded %d OUI entries from %s\n", count, localPath)
}

// LookupManufacturer 查找MAC地址制造商
func lookupManufacturer(mac string) string {
	// 规范化MAC地址格式
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	mac = strings.ReplaceAll(mac, "-", "")

	if len(mac) < 6 {
		log.Printf("[MAC] Invalid MAC address: %s\n", mac)
		return "Unknown"
	}

	// 获取OUI（前6位）
	oui := mac[:6]

	db := GetOUIDatabase()
	db.mu.RLock()
	defer db.mu.RUnlock()

	if !db.initialized {
		log.Println("[MAC] OUI database not initialized")
		return ""
	}

	if manufacturer, ok := db.manufacturers[oui]; ok {
		log.Printf("[MAC] Found manufacturer for %s: %s\n", mac, manufacturer)
		return manufacturer
	}

	log.Printf("[MAC] No manufacturer found for MAC: %s (OUI: %s)\n", mac, oui)
	return ""
}
