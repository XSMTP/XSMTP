package xsmtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// mockServer 模拟SMTP服务器用于测试
type mockServer struct {
	listener net.Listener
	done     chan struct{}
}

func newMockServer(t *testing.T) *mockServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	server := &mockServer{
		listener: listener,
		done:     make(chan struct{}),
	}

	go server.serve(t)
	return server
}

func (s *mockServer) serve(t *testing.T) {
	defer close(s.done)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handleConnection(t, conn)
	}
}

func (s *mockServer) handleConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// 发送初始问候语
	fmt.Fprintf(conn, "220 smtp.gmail.com ESMTP ready\r\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "EHLO"):
			fmt.Fprintf(conn, "250-smtp.gmail.com\r\n")
			fmt.Fprintf(conn, "250-STARTTLS\r\n")
			fmt.Fprintf(conn, "250-AUTH PLAIN LOGIN\r\n")
			fmt.Fprintf(conn, "250 8BITMIME\r\n")
		case line == "STARTTLS":
			fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\r\n")
			return // 在实际测试中，这里应该进行TLS升级
		case strings.HasPrefix(line, "AUTH PLAIN"):
			fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n")
		case line == "QUIT":
			fmt.Fprintf(conn, "221 2.0.0 Bye\r\n")
			return
		default:
			fmt.Fprintf(conn, "500 5.5.1 Unknown command\r\n")
		}
	}
}

func (s *mockServer) close() {
	s.listener.Close()
	<-s.done
}

func TestNewClient(t *testing.T) {
	config := &ClientConfig{
		Protocol:   "xsmtp",
		ServerIP:   "127.0.0.1",
		ServerPort: 587,
		Username:   "test",
		Password:   "test123",
	}

	client := NewClient(config)

	if client.config != config {
		t.Errorf("NewClient() config = %v, want %v", client.config, config)
	}

	if client.udpCounter != 0 {
		t.Errorf("NewClient() udpCounter = %d, want 0", client.udpCounter)
	}

	if client.isXSMTP {
		t.Error("NewClient() isXSMTP should be false")
	}
}

func TestClientConnect(t *testing.T) {
	// 启动模拟服务器
	server := newMockServer(t)
	defer server.close()

	host, port, _ := net.SplitHostPort(server.listener.Addr().String())
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)

	config := &ClientConfig{
		Protocol:   "xsmtp",
		ServerIP:   host,
		ServerPort: portNum,
		Username:   "test",
		Password:   "test123",
	}

	client := NewClient(config)

	// 测试连接
	err := client.Connect()
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if !client.isXSMTP {
		t.Error("Connect() client should be in XSMTP mode")
	}
}

func TestClientCreateTCPProxy(t *testing.T) {
	client := &Client{
		isXSMTP: false,
		conn:    &mockConn{},
	}

	// 测试未连接状态
	if _, err := client.CreateTCPProxy("example.com:80"); err == nil {
		t.Error("CreateTCPProxy() should fail when not in XSMTP mode")
	}

	// 设置为已连接状态
	client.isXSMTP = true

	// 测试正常代理创建
	conn, err := client.CreateTCPProxy("example.com:80")
	if err != nil {
		t.Fatalf("CreateTCPProxy() error = %v", err)
	}

	if conn == nil {
		t.Error("CreateTCPProxy() returned nil connection")
	}
}

func TestClientSendUDP(t *testing.T) {
	client := &Client{
		isXSMTP: false,
		conn:    &mockConn{},
	}

	// 测试未连接状态
	if err := client.SendUDP(1, "8.8.8.8:53", []byte("test")); err == nil {
		t.Error("SendUDP() should fail when not in XSMTP mode")
	}

	// 设置为已连接状态
	client.isXSMTP = true

	// 测试UDP发送
	err := client.SendUDP(1, "8.8.8.8:53", []byte("test"))
	if err != nil {
		t.Fatalf("SendUDP() error = %v", err)
	}
}

// mockConn 实现net.Conn接口用于测试
type mockConn struct {
	net.Conn
	closed bool
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
