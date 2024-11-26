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
	embeddedFile  = "oui.txt.gz"
)

type OUIDatabase struct {
	manufacturers map[string]string
	mu            sync.RWMutex
	initialized   bool
}

var (
	ouiDB     *OUIDatabase
	ouiDBOnce sync.Once
)

func extractEmbeddedData() error {
	if err := os.MkdirAll(localDataDir, 0755); err != nil {
		return err
	}

	localPath := filepath.Join(localDataDir, localDataFile)

	if _, err := os.Stat(localPath); err == nil {
		log.Printf("[MAC] Using existing local database: %s\n", localPath)
		return nil
	}

	compressedFile, err := ouiData.Open(embeddedFile)
	if err != nil {
		return err
	}
	defer compressedFile.Close()

	gzReader, err := gzip.NewReader(compressedFile)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	outFile, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, gzReader)
	return err
}

func GetOUIDatabase() *OUIDatabase {
	ouiDBOnce.Do(func() {
		ouiDB = &OUIDatabase{
			manufacturers: make(map[string]string),
		}
		ouiDB.loadDatabase()
	})
	return ouiDB
}

func (db *OUIDatabase) loadDatabase() {
	log.Println("[MAC] Loading OUI database...")

	if err := extractEmbeddedData(); err != nil {
		log.Printf("[MAC] Failed to extract embedded data: %v\n", err)
		return
	}

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

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			log.Printf("[MAC] Invalid line format: %s", line)
			continue
		}

		oui := strings.TrimSpace(parts[0])
		manufacturer := strings.TrimSpace(parts[1])

		db.manufacturers[oui] = manufacturer
		count++
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[MAC] Scanner error: %v", err)
	}

	db.initialized = true
	log.Printf("[MAC] Loaded %d OUI entries from %s\n", count, localPath)
}

func lookupManufacturer(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	mac = strings.ReplaceAll(mac, "-", "")

	if len(mac) < 6 {
		log.Printf("[MAC] Invalid MAC address: %s\n", mac)
		return "Unknown"
	}

	oui := mac[:6]

	db := GetOUIDatabase()
	db.mu.RLock()
	defer db.mu.RUnlock()

	if !db.initialized {
		log.Println("[MAC] OUI database not initialized")
		return ""
	}

	if manufacturer, ok := db.manufacturers[oui]; ok {
		return manufacturer
	}

	log.Printf("[MAC] No manufacturer found for MAC: %s (OUI: %s)\n", mac, oui)
	return ""
}
