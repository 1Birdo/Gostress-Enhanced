package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"
)

const (
	PROXY_LISTEN    = "0.0.0.0:7003"
	SERVER_ADDR     = "192.168.1.50:7002"
	CONNECT_TIMEOUT = 10 * time.Second
	IO_TIMEOUT      = 30 * time.Second
	CERT_FILE       = "server.crt" // Need certs for proxy
	KEY_FILE        = "server.key"
)

func main() {
	// Load proxy's TLS certificate
	cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	if err != nil {
		log.Fatalf("Failed to load TLS cert: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Listen for TLS connections from bots
	listener, err := tls.Listen("tcp", PROXY_LISTEN, config)
	if err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	defer listener.Close()
	log.Printf("TLS proxy listening on %s", PROXY_LISTEN)

	for {
		botConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(botConn)
	}
}

func handleConnection(botConn net.Conn) {
	defer botConn.Close()

	// Connect to real server with TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	serverConn, err := tls.Dial("tcp", SERVER_ADDR, tlsConfig)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer serverConn.Close()

	// Set timeouts
	botConn.SetDeadline(time.Now().Add(IO_TIMEOUT))
	serverConn.SetDeadline(time.Now().Add(IO_TIMEOUT))

	// Bidirectional forwarding
	done := make(chan struct{})
	go func() { io.Copy(serverConn, botConn); done <- struct{}{} }()
	go func() { io.Copy(botConn, serverConn); done <- struct{}{} }()
	<-done
}
