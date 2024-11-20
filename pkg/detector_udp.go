package zasset

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type UdpDetector struct {
	BaseDetector
}

func NewUdpDetector(timeout time.Duration) *UdpDetector {
	return &UdpDetector{
		BaseDetector: BaseDetector{timeout: timeout},
	}
}
func (a *UdpDetector) Name() string {
	return "UdpDetector"
}

func (d *UdpDetector) Detect(cidr string) ([]stage.Node, error) {
	// 解析 CIDR 地址
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("[UDP] failed to parse CIDR %s: %v", cidr, err)
		return nil, err
	}

	var nodes []stage.Node

	// 遍历 CIDR 范围内的所有 IP 地址
	var wg sync.WaitGroup
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:1900", ip.String())
			conn, err := net.Dial("udp", addr)
			if err != nil {
				log.Printf("[UDP] failed to connect to %s: %v", addr, err)
				return
			}
			defer conn.Close()

			// 发送 SSDP M-SEARCH 请求
			request := "M-SEARCH * HTTP/1.1\r\n" +
				"HOST: 239.255.255.250:1900\r\n" +
				"MAN: \"ssdp:discover\"\r\n" +
				"MX: 3\r\n" +
				"ST: ssdp:all\r\n\r\n"

			_, err = conn.Write([]byte(request))
			if err != nil {
				log.Printf("[UDP] failed to send request to %s: %v", addr, err)
				return
			}

			// 设置读取超时
			conn.SetDeadline(time.Now().Add(1 * time.Second))

			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				//log.Printf("[UDP] failed to read response from %s: %v", addr, err)
				return
			}

			response := string(buffer[:n])
			log.Printf("[UDP] received response from %s: %s", addr, response)

			node := stage.Node{
				IP:       ip.String(),
				OS:       "Unknown", // 根据响应解析操作系统信息
				Hostname: "Unknown", // 根据响应解析主机名
				Ports: []*stage.ServiceInfo{
					{
						Port:     1900,  // SSDP 默认端口
						Protocol: "udp", // 协议
					},
				},
			}
			nodes = append(nodes, node)
		}(ip)
	}
	wg.Wait()

	return nodes, nil
}
