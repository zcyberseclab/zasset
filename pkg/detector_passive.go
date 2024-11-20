package zasset

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

// PassiveDetector 被动探测器
type PassiveDetector struct {
	BaseDetector
	iface  string
	assets map[string]*stage.Node
	mu     sync.Mutex
}

// NewPassiveDetector 创建新的被动探测器
func NewPassiveDetector(iface string) *PassiveDetector {
	return &PassiveDetector{
		BaseDetector: BaseDetector{timeout: 5 * time.Minute},
		iface:        iface,
		assets:       make(map[string]*stage.Node),
	}
}

func (p *PassiveDetector) Name() string {
	return "PassiveDetector"
}
func (p *PassiveDetector) getNodes() ([]stage.Node, error) {
	log.Printf("[Passive] Getting collected nodes...\n")
	// Implementation for getting nodes
	// You'll need to implement the logic to retrieve nodes
	return nil, nil
}

func (p *PassiveDetector) Detect(target string) ([]stage.Node, error) {
	log.Printf("[Passive] ====== Starting passive detection for target: %s ======\n", target)
	log.Printf("[Passive] Using interface: %s with timeout: %v\n", p.iface, p.timeout)

	handle, err := p.openInterface()
	if err != nil {
		log.Printf("[Passive] Failed to open interface: %v\n", err)
		return nil, err
	}
	defer handle.Close()

	err = p.capturePackets(handle)
	if err != nil {
		log.Printf("[Passive] Error capturing packets: %v\n", err)
		return nil, err
	}

	nodes, err := p.getNodes()
	if err != nil {
		log.Printf("[Passive] Error getting nodes: %v\n", err)
		return nil, err
	}

	log.Printf("[Passive] Detection completed. Found %d nodes\n", len(nodes))
	return nodes, err
}

func (p *PassiveDetector) capturePackets(handle *pcap.Handle) error {
	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 创建一个map来存储已发现的设备，避免重复处理
	discovered := make(map[string]*stage.Node)
	var mu sync.Mutex // 添加互斥锁保护map

	fmt.Println("\nStarting packet capture. Discovering devices...")
	fmt.Println("----------------------------------------")

	// 设置超时通道
	timeout := time.After(p.timeout)

	for {
		select {
		case <-timeout:
			// 转换discovered map为节点列表
			var nodes []stage.Node
			mu.Lock()
			for _, node := range discovered {
				nodes = append(nodes, *node)
			}
			mu.Unlock()

			// 保存到p.assets
			p.mu.Lock()
			for ip, node := range discovered {
				p.assets[ip] = node
			}
			p.mu.Unlock()

			return nil

		default:
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				return nil
			} else if err != nil {
				continue
			}

			// 获取以太网层
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer == nil {
				continue
			}
			eth := ethernetLayer.(*layers.Ethernet)

			// 忽略广播地址
			if eth.DstMAC.String() == "ff:ff:ff:ff:ff:ff" {
				continue
			}

			// 忽略组播地址
			if eth.DstMAC[0]&0x01 == 1 {
				continue
			}

			// 获取IP层
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip := ipLayer.(*layers.IPv4)

			// 忽略本地回环地址
			if ip.SrcIP.IsLoopback() || ip.DstIP.IsLoopback() {
				continue
			}

			// 处理源设备
			p.processNode(eth.SrcMAC, ip.SrcIP, discovered, &mu)

			// 处理目标设备
			p.processNode(eth.DstMAC, ip.DstIP, discovered, &mu)
		}
	}
}

// 处理单个节点的辅助函数
func (p *PassiveDetector) processNode(mac net.HardwareAddr, ip net.IP, discovered map[string]*stage.Node, mu *sync.Mutex) {
	// 检查是否为内网地址
	if !isPrivateIP(ip) {
		return
	}

	ipStr := ip.String()
	macStr := mac.String()

	mu.Lock()
	defer mu.Unlock()

	// 检查是否已经发现过这个IP
	if _, exists := discovered[ipStr]; !exists {
		// 创建新的Node
		node := &stage.Node{
			IP:  ipStr,
			MAC: macStr,
		}

		// 标准化 MAC 地址格式并查找制造商信息
		manufacturer := lookupManufacturer(macStr)
		if manufacturer != "" {
			node.Manufacturer = manufacturer

		}

		discovered[ipStr] = node

		// 打印发现的设备信息
		fmt.Printf("New internal device discovered:\n")
		fmt.Printf("  IP: %s\n", ipStr)
		fmt.Printf("  MAC: %s\n", macStr)
		if node.Manufacturer != "" {
			fmt.Printf("  Manufacturer: %s\n", node.Manufacturer)
		}
		if node.Devicetype != "" {
			fmt.Printf("  Device Type: %s\n", node.Devicetype)
		}
		fmt.Println("----------------------------------------")
	}
}

// 检查是否为内网地址
func isPrivateIP(ip net.IP) bool {
	// 定义内网地址范围
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{
			net.ParseIP("10.0.0.0"),
			net.ParseIP("10.255.255.255"),
		},
		{
			net.ParseIP("172.16.0.0"),
			net.ParseIP("172.31.255.255"),
		},
		{
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.255.255"),
		},
	}

	// 转换为IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	// 检查是否在内网范围内
	for _, r := range privateRanges {
		if bytes.Compare(ipv4, r.start.To4()) >= 0 && bytes.Compare(ipv4, r.end.To4()) <= 0 {
			return true
		}
	}

	return false
}

func (p *PassiveDetector) openInterface() (*pcap.Handle, error) {
	// 获取所有网络接口
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to find network devices: %v", err)
	}

	// 找到第一个可用的接口
	var device string
	for _, dev := range devices {
		// 检查是否为回环接口
		isLoopback := false
		for _, addr := range dev.Addresses {
			if addr.IP.IsLoopback() {
				isLoopback = true
				break
			}
		}
		if isLoopback {
			continue
		}

		// 确保接口有IPv4地址
		for _, addr := range dev.Addresses {
			if addr.IP.To4() != nil {
				device = dev.Name
				break
			}
		}
		if device != "" {
			break
		}
	}

	if device == "" {
		return nil, fmt.Errorf("no suitable network interface found")
	}

	// 打开接口
	handle, err := pcap.OpenLive(
		device,            // 设备名
		65536,             // snapshot length
		true,              // promiscuous mode
		pcap.BlockForever, // timeout
	)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", device, err)
	}

	return handle, nil
}
