package zasset

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/zcyberseclab/zscan/pkg/stage"
)

type PingDetector struct {
	BaseDetector
}

func NewPingDetector() *PingDetector {
	return &PingDetector{
		BaseDetector: BaseDetector{},
	}
}

func (p *PingDetector) sendPingRequests(ctx context.Context, ips []string) ([]stage.Node, error) {

	resultChan := make(chan stage.Node, len(ips))
	errChan := make(chan error, len(ips))

	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 50)

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

			// 发送 Ping 请求
			if err := ping(ip); err != nil {
				errChan <- err
				return
			}

			// 如果 Ping 成功，创建 Node 对象
			node := stage.Node{
				IP: ip,
			}
			resultChan <- node
		}(ipStr)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	// 收集结果
	var nodes []stage.Node
	var errs []error

	for {
		select {
		case node, ok := <-resultChan:
			if !ok {

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

	return nodes, nil
}

func ping(ip string) error {

	conn, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 构造 ICMP Echo 请求
	msg := []byte{8, 0, 0, 0, 0, 0, 0, 0} // Type 8: Echo Request
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	reply := make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	if reply[20] != 0 { // Type 0: Echo Reply
		return fmt.Errorf("received unexpected response")
	}

	return nil
}

func (p *PingDetector) Name() string {
	return "PingDetector"
}

func (p *PingDetector) Detect(target string) ([]stage.Node, error) {

	var targets []string

	if _, ipnet, err := net.ParseCIDR(target); err == nil {

		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			targets = append(targets, ip.String())
		}
	} else {

		targets = append(targets, target)
	}

	// Create a context
	ctx := context.Background()

	nodes, err := p.sendPingRequests(ctx, targets)
	if err != nil {
		log.Printf("[Ping] Error during detection: %v\n", err)
		return nil, err
	}

	log.Printf("[Ping] Detection completed. Found %d nodes\n", len(nodes)) // 只在结果汇总时打印
	for i := 0; i < len(nodes); i++ {
		log.Printf("[Ping] Found node: %s\n", nodes[i].IP)

	}
	return nodes, err
}
