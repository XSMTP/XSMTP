package xsmtp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 创建测试用的TLS证书
func createTestCert(t *testing.T) (string, string) {
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// 生成证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// 写入证书文件
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()

	// 写入私钥文件
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		t.Fatal(err)
	}
	keyOut.Close()

	return certFile, keyFile
}

func TestNewServer(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	config := &ServerConfig{
		Protocol:          "xsmtp",
		ServerIP:          "127.0.0.1",
		ServerPort:        0, // 使用0让系统分配端口
		MasqueradeHostname: "smtp.gmail.com",
		Username:          "test",
		Password:          "test123",
		UDPRelay:          true,
	}

	server, err := NewServer(config, certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server.config != config {
		t.Errorf("NewServer() config = %v, want %v", server.config, config)
	}

	if server.tlsConfig == nil {
		t.Error("NewServer() tlsConfig is nil")
	}

	if server.udpSessions == nil {
		t.Error("NewServer() udpSessions is nil")
	}

	if server.stopCh == nil {
		t.Error("NewServer() stopCh is nil")
	}
}

func TestServerStartStop(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	config := &ServerConfig{
		Protocol:          "xsmtp",
		ServerIP:          "127.0.0.1",
		ServerPort:        0,
		MasqueradeHostname: "smtp.gmail.com",
		Username:          "test",
		Password:          "test123",
		UDPRelay:          true,
	}

	server, err := NewServer(config, certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// 测试启动服务器
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !server.running {
		t.Error("Start() server not running")
	}

	// 测试重复启动
	if err := server.Start(); err == nil {
		t.Error("Start() should fail when server is already running")
	}

	// 获取服务器地址
	addr := server.listener.Addr().String()
	
	// 测试连接
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	conn.Close()

	// 测试停止服务器
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if server.running {
		t.Error("Stop() server still running")
	}

	// 测试重复停止
	if err := server.Stop(); err == nil {
		t.Error("Stop() should fail when server is not running")
	}

	// 验证无法再连接
	if _, err := net.Dial("tcp", addr); err == nil {
		t.Error("Should not be able to connect after server is stopped")
	}
}

func TestUDPSessionCleanup(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	config := &ServerConfig{
		Protocol:          "xsmtp",
		ServerIP:          "127.0.0.1",
		ServerPort:        0,
		MasqueradeHostname: "smtp.gmail.com",
		Username:          "test",
		Password:          "test123",
		UDPRelay:          true,
	}

	server, err := NewServer(config, certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// 添加一些UDP会话
	server.udpMu.Lock()
	server.udpSessions[1] = &udpSession{
		conn:     &mockPacketConn{},
		lastUsed: time.Now().Add(-15 * time.Minute), // 过期会话
	}
	server.udpSessions[2] = &udpSession{
		conn:     &mockPacketConn{},
		lastUsed: time.Now(), // 活跃会话
	}
	server.udpMu.Unlock()

	// 启动服务器（会启动清理协程）
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// 等待清理周期
	time.Sleep(100 * time.Millisecond)

	server.udpMu.Lock()
	sessionCount := len(server.udpSessions)
	server.udpMu.Unlock()

	if sessionCount != 1 {
		t.Errorf("UDP session cleanup failed, got %d sessions, want 1", sessionCount)
	}

	server.Stop()
}

// mockPacketConn 实现net.PacketConn接口用于测试
type mockPacketConn struct {
	net.PacketConn
	closed bool
}

func (m *mockPacketConn) Close() error {
	m.closed = true
	return nil
}

func TestServerHandleConnection(t *testing.T) {
	certFile, keyFile := createTestCert(t)

	config := &ServerConfig{
		Protocol:          "xsmtp",
		ServerIP:          "127.0.0.1",
		ServerPort:        0,
		MasqueradeHostname: "smtp.gmail.com",
		Username:          "test",
		Password:          "test123",
		UDPRelay:          true,
	}

	server, err := NewServer(config, certFile, keyFile)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer server.Stop()

	// 创建客户端配置
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 连接到服务器
	conn, err := tls.Dial("tcp", server.listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// TODO: 实现完整的SMTP握手测试
	// 这部分需要模拟完整的SMTP客户端行为
}
