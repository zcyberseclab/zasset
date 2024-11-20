package zasset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

const (
	// 海康威视SADP协议
	HikPort        = 37020
	HikListenPort  = 37020
	HikMulticastIP = "239.255.255.250"

	// 大华设备
	DahuaPort        = 37810
	DahuaListenPort  = 37809
	DahuaMulticastIP = "239.255.255.251"
)

type CameraDetector struct {
	BaseDetector
	connMutex sync.Mutex
}

var dahuaReq = "20000000444849500000000000000000490000000000000049000000000000007b20226d6574686f6422203a20224448446973636f7665722e736561726368222c2022706172616d7322203a207b20226d616322203a2022222c2022756e6922203a2031207d207d0a"

func (d *CameraDetector) detectHikvision(conn *net.UDPConn) ([]stage.Node, error) {
	// 创建多播地址
	rAddr := &net.UDPAddr{
		IP:   net.ParseIP(HikMulticastIP),
		Port: HikPort,
	}

	// 构造探测包
	uid, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %v", err)
	}

	reqData := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
		<Probe>
			<Uuid>%s</Uuid>
			<Types>inquiry</Types>
		</Probe>`, uid.String())

	d.connMutex.Lock()
	_, err = conn.WriteToUDP([]byte(reqData), rAddr)
	d.connMutex.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to send Hikvision probe: %v", err)
	}

	return d.receiveResponses(conn, "hikvision")
}

func (d *CameraDetector) detectDahua(conn *net.UDPConn) ([]stage.Node, error) {
	// 创建多播地址
	rAddr := &net.UDPAddr{
		IP:   net.ParseIP(DahuaMulticastIP),
		Port: DahuaPort,
	}

	// 将十六进制字符串转换为字节数组
	sendData, err := hex.DecodeString(dahuaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Dahua probe data: %v", err)
	}

	d.connMutex.Lock()
	_, err = conn.WriteToUDP(sendData, rAddr)
	d.connMutex.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to send Dahua probe: %v", err)
	}

	return d.receiveResponses(conn, "dahua")
}

func (d *CameraDetector) receiveResponses(conn *net.UDPConn, manufacturer string) ([]stage.Node, error) {
	var nodes []stage.Node
	buffer := make([]byte, 2048)

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(d.timeout))

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			break // 超时或其他错误
		}

		// 解析响应
		node := &stage.Node{
			IP:           remoteAddr.IP.String(),
			Devicetype:   "ipcamera",
			Manufacturer: manufacturer,
		}

		// 根据制造商解析具体信息
		if manufacturer == "hikvision" {
			if bytes.HasPrefix(buffer[:n], []byte("HK")) {
				d.parseHikvisionResponse(buffer[:n], node)
				nodes = append(nodes, *node)
			}
		} else if manufacturer == "dahua" {
			if bytes.HasPrefix(buffer[:n], []byte("DH")) {
				d.parseDahuaResponse(buffer[:n], node)
				nodes = append(nodes, *node)
			}
		}
	}

	return nodes, nil
}

func (d *CameraDetector) parseHikvisionResponse(data []byte, node *stage.Node) {
	// 解析海康威视设备响应
	// 通常包含：设备型号、序列号、固件版本等信息
	if modelInfo := extractModelInfo(data, "Model="); modelInfo != "" {
		node.Model = modelInfo
	}
}

func (d *CameraDetector) parseDahuaResponse(data []byte, node *stage.Node) {
	// 解析大华设备响应
	// 通常包含：设备型号、序列号、固件版本等信息
	if modelInfo := extractModelInfo(data, "Device="); modelInfo != "" {
		node.Model = modelInfo
	}
}

func extractModelInfo(data []byte, prefix string) string {
	modelIndex := bytes.Index(data, []byte(prefix))
	if modelIndex == -1 {
		return ""
	}

	endIndex := bytes.Index(data[modelIndex:], []byte("\x00"))
	if endIndex == -1 {
		return ""
	}

	return string(data[modelIndex+len(prefix) : modelIndex+endIndex])
}

func NewCameraDetector(timeout time.Duration) *CameraDetector {
	return &CameraDetector{
		BaseDetector: BaseDetector{timeout: timeout},
	}
}

func (d *CameraDetector) Name() string {
	return "CameraDetector"
}

// Add this method to implement the Detector interface
func (d *CameraDetector) Detect(target string) ([]stage.Node, error) {
	// 创建通道
	hikNodes := make(chan []stage.Node, 1)
	dahuaNodes := make(chan []stage.Node, 1)
	hikErr := make(chan error, 1)
	dahuaErr := make(chan error, 1)

	// 启动海康威视探测
	go func() {
		// 为海康威视创建专用连接
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: HikListenPort,
		})
		if err != nil {
			hikNodes <- nil
			hikErr <- fmt.Errorf("failed to create Hikvision UDP connection: %v", err)
			return
		}
		defer conn.Close()

		nodes, err := d.detectHikvision(conn)
		hikNodes <- nodes
		hikErr <- err
	}()

	// 启动大华探测
	go func() {
		// 为大华创建专用连接
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: DahuaListenPort,
		})
		if err != nil {
			dahuaNodes <- nil
			dahuaErr <- fmt.Errorf("failed to create Dahua UDP connection: %v", err)
			return
		}
		defer conn.Close()

		nodes, err := d.detectDahua(conn)
		dahuaNodes <- nodes
		dahuaErr <- err
	}()

	// 收集结果
	var nodes []stage.Node

	// 添加超时控制
	timeout := time.After(d.timeout)

	// 使用select来处理结果和超时
	var hikResult, dahuaResult []stage.Node
	var err1, err2 error

	// 等待两个结果或超时
	for i := 0; i < 2; i++ {
		select {
		case hikResult = <-hikNodes:
			err1 = <-hikErr
			nodes = append(nodes, hikResult...)
		case dahuaResult = <-dahuaNodes:
			err2 = <-dahuaErr
			nodes = append(nodes, dahuaResult...)
		case <-timeout:
			return nodes, fmt.Errorf("detection timeout after %v", d.timeout)
		}
	}

	// 处理错误
	if err1 != nil && err2 != nil {
		return nodes, fmt.Errorf("detection failed: hikvision: %v, dahua: %v", err1, err2)
	}

	return nodes, nil
}
