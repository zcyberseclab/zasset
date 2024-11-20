package zasset

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type OSDetector struct {
	BaseDetector
	probes []ProbeMethod
}

type ProbeMethod struct {
	Name   string
	Probe  func(string) (string, string, error)
	Weight int // 权重，用于多个探测结果的决策
}

func NewOSDetector(timeout time.Duration) *OSDetector {
	d := &OSDetector{
		BaseDetector: BaseDetector{timeout: timeout},
	}

	// 注册探测方法
	d.probes = []ProbeMethod{
		{"ICMP", d.probeICMP, 3},
		//{"TCPStack", d.probeTCPStack, 2},
		{"SMB", d.probeSMB, 2},
	}

	return d
}

func (d *OSDetector) Detect(target string) ([]stage.Node, error) {
	// 解析CIDR
	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		// 如果不是CIDR，就当作单个IP处理
		return d.detectSingle(target)
	}

	var nodes []stage.Node
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 创建工作池，限制并发数
	semaphore := make(chan struct{}, 20) // 限制20个并发

	// 遍历CIDR范围内的所有IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			// 执行单个IP的检测
			results, err := d.detectSingle(ip)
			if err != nil {
				fmt.Printf("Error detecting %s: %v\n", ip, err)
				return
			}

			// 安全地添加结果到切片中
			mutex.Lock()
			nodes = append(nodes, results...)
			mutex.Unlock()
		}(ip.String())
	}

	wg.Wait()
	return nodes, nil
}

// 单个IP的检测逻辑
func (d *OSDetector) detectSingle(target string) ([]stage.Node, error) {
	node := stage.Node{
		IP: target,
	}

	results := make(map[string]int)
	osSource := make(map[string]string)

	fmt.Printf("\n[+] Starting OS detection for target: %s\n", target)

	// 执行所有探测
	for _, probe := range d.probes {
		fmt.Printf("\n[-] Running %s probe...\n", probe.Name)
		os, deviceType, err := probe.Probe(target)
		if err != nil {
			fmt.Printf("    Error: %v\n", err)
			continue
		}

		if os != "" {
			results[os] += probe.Weight
			if existing, ok := osSource[os]; ok {
				osSource[os] = existing + ", " + probe.Name
			} else {
				osSource[os] = probe.Name
			}
			fmt.Printf("    Detected OS: %s (Weight: %d)\n", os, probe.Weight)
		} else {
			fmt.Printf("    No OS detected\n")
		}

		if deviceType != "" {
			fmt.Printf("    Device Type: %s\n", deviceType)
			if node.Devicetype == "" {
				node.Devicetype = deviceType
			}
		}
	}

	fmt.Printf("\n[+] Detection Results Summary:\n")
	for os, weight := range results {
		fmt.Printf("    %s: Weight = %d (Source: %s)\n", os, weight, osSource[os])
	}

	// 选择权重最高的OS
	maxWeight := 0
	var detectedOS string
	var finalSource string
	for os, weight := range results {
		if weight > maxWeight {
			maxWeight = weight
			detectedOS = os
			finalSource = osSource[os]
		}
	}
	node.OS = detectedOS

	fmt.Printf("\n[+] Final Detection Result:\n")
	fmt.Printf("    IP: %s\n", node.IP)
	fmt.Printf("    OS: %s (Detected by: %s)\n", node.OS, finalSource)
	fmt.Printf("    Device Type: %s\n", node.Devicetype)
	fmt.Println("----------------------------------------")

	return []stage.Node{node}, nil
}

// ICMP探测
func (d *OSDetector) probeICMP(target string) (string, string, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return "", "", err
	}

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return "", "", err
	}

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return "", "", err
	}

	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(d.timeout))
	if err != nil {
		return "", "", err
	}

	_, _, err = conn.ReadFrom(reply)
	if err != nil {
		return "", "", err
	}

	// 基于TTL和响应时间推断OS
	ttl := reply[8] // TTL字段

	switch {
	case ttl <= 64:
		return "linux", "", nil
	case ttl <= 128:
		return "windows", "", nil
	case ttl <= 255:
		return "cisco", "Router", nil
	}

	return "", "", nil
}

// TCP栈指纹探测
func (d *OSDetector) probeTCPStack(target string) (string, string, error) {
	// 常用端口列表
	ports := []int{80, 443, 22, 21, 23}

	type tcpFeatures struct {
		windowSize  int
		ttl         int
		mss         int
		windowScale int
		timestamp   bool
		sackPerm    bool
	}

	var features tcpFeatures

	// 尝试连接多个端口
	for _, port := range ports {
		dialer := net.Dialer{
			Timeout: d.timeout,
		}

		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
		fmt.Printf("    Dialing %s:%d\n", target, port)
		if err != nil {
			continue
		}
		defer conn.Close()

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			continue
		}

		// 获取TCP连接信息
		if err := tcpConn.SetNoDelay(true); err != nil {
			continue
		}

		// 尝试获取TCP选项
		rawConn, err := tcpConn.SyscallConn()
		if err == nil {
			rawConn.Control(func(fd uintptr) {
				// 获取TCP信息 (系统特定)
				// 这里使用示例值，实际实现需要根据操作系统调用相应的系统调用
				features.windowSize = 65535 // 示例值
				features.mss = 1460         // 示例值
				features.windowScale = 7    // 示例值
				features.timestamp = true   // 示例值
				features.sackPerm = true    // 示例值
			})
		}

		// 找到一个可用端口就退出
		break
	}

	// 基于收集到的特征进行操作系统判断
	switch {
	case features.windowSize >= 65535 && features.windowScale >= 7 && features.timestamp:
		// Linux/Ubuntu 特征 - 更宽松的匹配条件
		fmt.Printf("    TCP Features - Window: %d, Scale: %d, MSS: %d, SACK: %v\n",
			features.windowSize, features.windowScale, features.mss, features.sackPerm)
		return "linux", "", nil

	case features.windowSize == 64240 && features.windowScale == 8:
		// Windows 特征
		fmt.Printf("    TCP Features - Window: %d, Scale: %d, MSS: %d, SACK: %v\n",
			features.windowSize, features.windowScale, features.mss, features.sackPerm)
		return "windows", "", nil

	case features.windowSize == 65535 && features.windowScale == 2:
		// FreeBSD 特征
		fmt.Printf("    TCP Features - Window: %d, Scale: %d, MSS: %d, SACK: %v\n",
			features.windowSize, features.windowScale, features.mss, features.sackPerm)
		return "freebsd", "", nil

	case features.windowSize <= 4096 && features.windowScale <= 2:
		// 只有在窗口大小很小且窗口缩放因子也小的情况下才判断为嵌入式设备
		fmt.Printf("    TCP Features - Window: %d, Scale: %d, MSS: %d, SACK: %v\n",
			features.windowSize, features.windowScale, features.mss, features.sackPerm)
		return "embedded", "IoT Device", nil
	}

	// 如果有特征但无法确定具体OS
	if features.windowSize > 0 {
		fmt.Printf("    TCP Features - Window: %d, Scale: %d, MSS: %d, SACK: %v\n",
			features.windowSize, features.windowScale, features.mss, features.sackPerm)
		return "", "", nil
	}

	return "", "", fmt.Errorf("no TCP features detected")
}

// SMB协议探测
func (d *OSDetector) probeSMB(target string) (string, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", target), d.timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	// SMB协议握手包
	negotiateProtocolRequest := []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42,
		0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		// ... 更多SMB协议数据 ...
	}

	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return "", "", err
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		return "", "", err
	}

	// 分析SMB响应
	if bytes.Contains(response, []byte("Windows")) {
		return "windows", "", nil
	}
	if bytes.Contains(response, []byte("Samba")) {
		return "linux", "", nil
	}

	return "", "", nil
}

func (d *OSDetector) Name() string {
	return "OSDetector"
}
