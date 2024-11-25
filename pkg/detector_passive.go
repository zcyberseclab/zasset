package zasset

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

type PassiveDetector struct {
	BaseDetector
	assets map[string]*stage.Node
	mu     sync.Mutex
}

func NewPassiveDetector() *PassiveDetector {
	return &PassiveDetector{
		BaseDetector: BaseDetector{},
		assets:       make(map[string]*stage.Node),
	}
}

func (p *PassiveDetector) Name() string {
	return "PassiveDetector"
}
func (p *PassiveDetector) getNodes() ([]stage.Node, error) {
	log.Printf("[Passive] Getting collected nodes...\n")

	p.mu.Lock()
	defer p.mu.Unlock()

	nodes := make([]stage.Node, 0, len(p.assets))
	for _, node := range p.assets {
		nodes = append(nodes, *node)
	}

	return nodes, nil
}

func (p *PassiveDetector) Detect(target string) ([]stage.Node, error) {

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
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	discovered := make(map[string]*stage.Node)
	var mu sync.Mutex

	fmt.Println("[passive] Starting packet capture...")

	// 创建一个done通道用于外部控制
	done := make(chan bool)
	defer close(done)

	// 启动一个goroutine来处理数据包
	go func() {
		for packet := range packetSource.Packets() {
			select {
			case <-done:
				return
			default:
				if packet == nil {
					continue
				}

				// ... 数据包处理代码 ...
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

				// 处理源设备和目标设备
				p.processNode(eth.SrcMAC, ip.SrcIP, discovered, &mu)
				p.processNode(eth.DstMAC, ip.DstIP, discovered, &mu)
			}
		}
	}()

	return nil
}

// 处理单个节点的辅助函数
func (p *PassiveDetector) processNode(mac net.HardwareAddr, ip net.IP, discovered map[string]*stage.Node, mu *sync.Mutex) {
	if !ip.IsPrivate() {
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

		manufacturer := lookupManufacturer(macStr)
		if manufacturer != "" {
			node.Manufacturer = manufacturer
		}

		// 添加到discovered map和assets
		discovered[ipStr] = node
		p.mu.Lock()
		p.assets[ipStr] = node
		p.mu.Unlock()

		// 打印发现信息
		fmt.Printf("[passive] New internal device discovered: IP=%s, MAC=%s\n", ipStr, macStr)

		// 获取reporter并上报新发现的节点
		reporter, err := GetMultiReporter()
		if err != nil {
			log.Printf("[passive] Failed to get reporter: %v\n", err)
			return
		}

		// 上报新节点，使用正确的函数签名
		if err := reporter.Report(node); err != nil {
			log.Printf("[passive] Failed to report new node: %v\n", err)
		}
	}
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
