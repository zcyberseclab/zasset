package zasset

import (
	"fmt"
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
