package zasset

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zcyberseclab/zscan/pkg/stage"
)

type ARPDetector struct {
	BaseDetector
	iface string
}

func NewARPDetector(iface string) *ARPDetector {
	return &ARPDetector{
		BaseDetector: BaseDetector{},
		iface:        iface,
	}
}

func (a *ARPDetector) sendARPRequests(ctx context.Context, ips []string) ([]stage.Node, error) {
	log.Printf("[ARP] Sending ARP requests to %d targets: %v\n", len(ips), ips)

	// 获取网络接口
	ifi, err := net.InterfaceByName(a.iface)
	if err != nil {
		log.Printf("[ARP] Failed to get interface %s: %v\n", a.iface, err)
		return nil, err
	}

	log.Printf("[ARP] Using interface: %s\n", ifi.Name)

	// 打开网络接口进行监听
	handle, err := pcap.OpenLive(a.iface, int32(1600), true, pcap.BlockForever)
	if err != nil {
		log.Printf("[ARP] Failed to open device: %v\n", err)
		return nil, err
	}
	defer handle.Close()

	// 创建结果通道和错误通道
	resultChan := make(chan stage.Node, len(ips))
	errChan := make(chan error, len(ips))

	// 使用 WaitGroup 等待所有 goroutine 完成
	var wg sync.WaitGroup

	// 限制并发数量，避免发送太多请求
	semaphore := make(chan struct{}, 50) // 最多50个并发

	// 并发发送 ARP 请求
	for _, ipStr := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查上下文是否已取消
			if ctx.Err() != nil {
				errChan <- ctx.Err()
				return
			}

			log.Printf("[ARP] Processing target: %s\n", ip)

			// 发送 ARP 请求
			arpRequest := gopacket.NewPacket([]byte{
				0x00, 0x01, // Hardware type (Ethernet)
				0x08, 0x00, // Protocol type (IPv4)
				0x06,       // Hardware size
				0x04,       // Protocol size
				0x00, 0x01, // Opcode (request)
				// Sender MAC address (fill with your MAC)
				0x70, 0xd8, 0x23, 0x87, 0xda, 0x00, // Replace with your MAC address
				// Sender IP address (fill with your IP)
				0xc0, 0xa8, 0x01, 0x01, // Replace with your IP address
				// Target MAC address (set to 0)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Target IP address
				net.ParseIP(ip).To4()[0], net.ParseIP(ip).To4()[1], net.ParseIP(ip).To4()[2], net.ParseIP(ip).To4()[3],
			}, layers.LayerTypeEthernet, gopacket.Default)

			// 发送 ARP 请求
			if err := handle.WritePacketData(arpRequest.Data()); err != nil {
				log.Printf("[ARP] Failed to send ARP request for %s: %v\n", ip, err)
				errChan <- err
				return
			}

			// 等待响应
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// 处理 ARP 响应
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					arpPacket, _ := arpLayer.(*layers.ARP)
					if arpPacket.Operation == layers.ARPReply { // ARP reply
						log.Printf("[ARP] Found device - IP: %s, MAC: %s\n", ip, net.HardwareAddr(arpPacket.SourceHwAddress).String())
						// 创建 Node 对象
						node := stage.Node{
							IP:           ip,
							MAC:          net.HardwareAddr(arpPacket.SourceHwAddress).String(),
							Manufacturer: lookupManufacturer(net.HardwareAddr(arpPacket.SourceHwAddress).String()),
						}
						resultChan <- node
						break
					}
				}
			}
		}(ipStr)
	}

	// 在另一个 goroutine 中等待所有请求完成并关闭通道
	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	// 收集结果
	var nodes []stage.Node
	var errs []error

	// 从通道读取结果和错误
	for {
		select {
		case node, ok := <-resultChan:
			if !ok {
				// 通道已关闭，退出循环
				goto Done
			}
			nodes = append(nodes, node)
		case err, ok := <-errChan:
			if !ok {
				continue
			}
			errs = append(errs, err)
		case <-ctx.Done():
			return nodes, ctx.Err()
		}
	}

Done:
	log.Printf("[ARP] Scan completed. Found %d devices\n", len(nodes))
	return nodes, nil
}

func (a *ARPDetector) Name() string {
	return "ARPDetector"
}

func (a *ARPDetector) Detect(target string) ([]stage.Node, error) {

	// Convert single target to slice
	targets := []string{target}

	// Create a context
	ctx := context.Background()

	nodes, err := a.sendARPRequests(ctx, targets)
	if err != nil {
		log.Printf("[ARP] Error during detection: %v\n", err)
		return nil, err
	}

	log.Printf("[ARP] Detection completed. Found %d nodes\n", len(nodes))
	return nodes, err
}
