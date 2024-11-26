package zasset

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"sync"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type DCERPCDetector struct {
	BaseDetector
}

func NewDCERPCDetector() *DCERPCDetector {
	return &DCERPCDetector{
		BaseDetector: BaseDetector{},
	}
}

func (d *DCERPCDetector) Detect(target string) ([]stage.Node, error) {
	const port = 135 // Replace with the appropriate port for your use case
	var nodes []stage.Node
	var mu sync.Mutex
	var wg sync.WaitGroup
	var targets []string

	// 检查目标是否为 CIDR 格式
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		// 展开 CIDR
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			targets = append(targets, ip.String())
		}
	} else {
		// 不是 CIDR 格式，直接添加目标
		targets = append(targets, target)
	}

	for _, ipStr := range targets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second)
			if err != nil {
				//log.Printf("[DCERPC]failed to connect to %s: %v", ip, err)
				return
			}
			client := rpc.NewClient(conn)
			defer client.Close()

			var reply string

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				done <- client.Call("Service.GetHostname", struct{}{}, &reply)
			}()

			select {
			case err = <-done:
				if err != nil {
					log.Printf("[DCERPC]failed to call GetHostname on %s: %v", ip, err)
					reply = ""
				}
			case <-ctx.Done():
				log.Printf("[DCERPC]timeout calling GetHostname on %s", ip)
				reply = ""
			}

			node := stage.Node{
				IP:       ip,
				OS:       "windows",
				Hostname: reply,
				Ports: []*stage.ServiceInfo{
					{
						Port:     port,
						Protocol: "dcerpc",
					},
				},
			}
			mu.Lock()
			nodes = append(nodes, node)
			mu.Unlock()
		}(ipStr)
	}

	wg.Wait()
	for _, node := range nodes {
		log.Printf("[DCERPC]Detected Node: IP=%s, Hostname=%s", node.IP, node.Hostname) // 打印每个节点的信息
	}

	return nodes, nil // 返回所有节点
}

func (d *DCERPCDetector) Name() string {
	return "DCERPCDetector"
}
