package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

const (
	SOCKS5_VERSION = 0x05
	NO_AUTH        = 0x00
	CONNECT        = 0x01
	IPV4           = 0x01
	DOMAIN         = 0x03
	IPV6           = 0x04
	SUCCESS        = 0x00
	FAILURE        = 0x01
	DEFAULT_PORT   = "1080"
)

// XOR-obfuscated auth key - replace with your own using the obfuscator
var obfuscatedAuthKey = []byte{
	0x54
}

var xorKey = []byte(" $ ")

type SOCKS5Proxy struct {
	server *tsnet.Server
}

// deobfuscateAuthKey decodes the embedded auth key
func deobfuscateAuthKey() string {
	return string(xorDecode(obfuscatedAuthKey))
}

// xorDecode performs XOR decoding with the static key
func xorDecode(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xorKey[i%len(xorKey)]
	}
	return result
}

// generateHostname creates a random hostname for the Tailscale node
func generateHostname() string {
	prefixes := []string{"web", "api", "cdn", "mail", "ftp", "db", "cache", "proxy", "gw", "vpn"}
	suffixes := []string{"srv", "node", "host", "box", "vm", "sys"}

	randBytes := make([]byte, 4)
	rand.Read(randBytes)

	prefixIdx := int(randBytes[0]) % len(prefixes)
	suffixIdx := int(randBytes[1]) % len(suffixes)
	num := int(randBytes[2])%100 + 1

	return fmt.Sprintf("%s-%s-%02d", prefixes[prefixIdx], suffixes[suffixIdx], num)
}

// getSystemHostname attempts to use the system hostname or generates a random one
func getSystemHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		hostname = strings.Split(hostname, ".")[0]
		hostname = strings.ReplaceAll(hostname, "_", "-")
		if len(hostname) > 0 && len(hostname) <= 63 {
			return hostname
		}
	}
	return generateHostname()
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy with Tailscale integration
func NewSOCKS5Proxy(hostname, authkey string) *SOCKS5Proxy {
	if hostname == "" {
		hostname = getSystemHostname()
	}

	if authkey == "" {
		authkey = deobfuscateAuthKey()
	}

	s := &tsnet.Server{
		Hostname: hostname,
		AuthKey:  authkey,
		Logf:     func(format string, args ...interface{}) {}, // Silent tsnet logs
	}
	return &SOCKS5Proxy{server: s}
}

// Start begins listening for SOCKS5 connections
func (p *SOCKS5Proxy) Start(port string) error {
	listener, err := p.server.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy active on %s:%s", p.server.Hostname, port)
	log.Printf("Waiting for AuthLoop...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go p.handleConnection(conn)
	}
}

// handleConnection processes a single SOCKS5 connection
func (p *SOCKS5Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial timeout for handshake
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: Handle authentication negotiation
	if err := p.handleAuth(conn); err != nil {
		return
	}

	// Step 2: Handle CONNECT request
	target, err := p.handleConnect(conn)
	if err != nil {
		return
	}

	// Step 3: Establish connection to target through Tailscale
	targetConn, err := p.server.Dial(context.Background(), "tcp", target)
	if err != nil {
		p.sendConnectResponse(conn, FAILURE, "0.0.0.0", "0")
		return
	}
	defer targetConn.Close()

	// Send success response
	if err := p.sendConnectResponse(conn, SUCCESS, "0.0.0.0", "0"); err != nil {
		return
	}

	// Remove timeouts for data transfer
	conn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})

	// Step 4: Relay data between client and target
	p.relay(conn, targetConn)
}

// handleAuth handles SOCKS5 authentication negotiation
func (p *SOCKS5Proxy) handleAuth(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	version := buf[0]
	nMethods := buf[1]

	if version != SOCKS5_VERSION {
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Check if NO_AUTH is supported
	noAuthSupported := false
	for _, method := range methods {
		if method == NO_AUTH {
			noAuthSupported = true
			break
		}
	}

	response := []byte{SOCKS5_VERSION, NO_AUTH}
	if !noAuthSupported {
		response[1] = 0xFF // No acceptable methods
		conn.Write(response)
		return fmt.Errorf("no acceptable authentication methods")
	}

	_, err := conn.Write(response)
	return err
}

// handleConnect handles the SOCKS5 CONNECT request
func (p *SOCKS5Proxy) handleConnect(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}

	version := buf[0]
	cmd := buf[1]
	// buf[2] is reserved
	addrType := buf[3]

	if version != SOCKS5_VERSION {
		return "", fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	if cmd != CONNECT {
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	var addr string
	switch addrType {
	case IPV4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = net.IP(ipBuf).String()

	case DOMAIN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainLen := lenBuf[0]
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		addr = string(domainBuf)

	case IPV6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = net.IP(ipBuf).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	return target, nil
}

// sendConnectResponse sends the SOCKS5 connect response
func (p *SOCKS5Proxy) sendConnectResponse(conn net.Conn, status byte, bindAddr, bindPort string) error {
	response := []byte{
		SOCKS5_VERSION, // Version
		status,         // Status
		0x00,           // Reserved
		IPV4,           // Address type (IPv4)
	}

	// Add bind address (4 bytes for IPv4)
	ip := net.ParseIP(bindAddr).To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	response = append(response, ip...)

	// Add bind port (2 bytes)
	port, _ := strconv.Atoi(bindPort)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	response = append(response, portBytes...)

	_, err := conn.Write(response)
	return err
}

// relay handles bidirectional data transfer between client and target
func (p *SOCKS5Proxy) relay(conn1, conn2 net.Conn) {
	done := make(chan struct{}, 2)

	// Copy data from conn1 to conn2
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn2, conn1)
	}()

	// Copy data from conn2 to conn1
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn1, conn2)
	}()

	// Wait for one direction to complete
	<-done
}

// printUsage displays usage information
func printUsage() {
	fmt.Printf("Usage: %s [hostname] [authkey]\n\n", os.Args[0])
	fmt.Println("  hostname: Optional. If blank, a random one will be generated")
	fmt.Println("  authkey : Optional. If blank, will use the built-in obfuscated key")
	fmt.Println()
	fmt.Println("Port is fixed at 1080.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s\n", os.Args[0])
	fmt.Println("    - Random hostname, embedded key")
	fmt.Println()
	fmt.Printf("  %s vpn-srv-01\n", os.Args[0])
	fmt.Println("    - Custom hostname, embedded key")
	fmt.Println()
	fmt.Printf("  %s shellbox-7 tskey-auth-1fXXXXXXXXXXXXXXXXXXXXXXXXXX\n", os.Args[0])
	fmt.Println("    - Custom hostname and runtime-supplied auth key")
}

func main() {
	var hostname, authkey string

	switch len(os.Args) {
	case 1:
		// Use defaults
	case 2:
		if os.Args[1] == "-h" || os.Args[1] == "--help" {
			printUsage()
			return
		}
		hostname = os.Args[1]
	case 3:
		hostname = os.Args[1]
		authkey = os.Args[2]
	default:
		printUsage()
		os.Exit(1)
	}

	proxy := NewSOCKS5Proxy(hostname, authkey)

	if hostname == "" {
		hostname = getSystemHostname()
	}
	log.Printf("Starting SockTail proxy as %s", hostname)
	log.Printf("Connecting to Tailscale network...")
	log.Printf("Proxy will be available on port %s once connected", DEFAULT_PORT)

	if err := proxy.Start(DEFAULT_PORT); err != nil {
		log.Fatalf("Proxy failed: %v", err)
	}
}
