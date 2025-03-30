package xsmtp

import (
    "bufio"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "io"
    "math/big"
    "net"
    "strings"
    "testing"
    "time"
)

// mockServer 模拟SMTP服务器用于测试
type mockServer struct {
    listener net.Listener
    done     chan struct{}
    cert     tls.Certificate
}

func (s *mockServer) handleConnection(t *testing.T, conn net.Conn) {
    defer conn.Close()

    // 发送初始问候语
    if _, err := fmt.Fprintf(conn, "220 smtp.gmail.com ESMTP ready\r\n"); err != nil {
        t.Errorf("Failed to send greeting: %v", err)
        return
    }

    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        line := scanner.Text()
        t.Logf("Received: %s", line)  // 添加调试日志

        switch {
        case strings.HasPrefix(line, "EHLO"):
            // 发送EHLO响应，确保包含STARTTLS
            responses := []string{
                "250-smtp.gmail.com",
                "250-SIZE 35882577",
                "250-8BITMIME",
                "250-STARTTLS",
                "250-AUTH PLAIN LOGIN",
                "250 ENHANCEDSTATUSCODES",
            }
            for _, resp := range responses {
                if _, err := fmt.Fprintf(conn, "%s\r\n", resp); err != nil {
                    t.Errorf("Failed to send EHLO response: %v", err)
                    return
                }
            }

        case line == "STARTTLS":
            if _, err := fmt.Fprintf(conn, "220 2.0.0 Ready to start TLS\r\n"); err != nil {
                t.Errorf("Failed to send STARTTLS response: %v", err)
                return
            }

            // 升级到TLS连接
            tlsConn := tls.Server(conn, &tls.Config{
                Certificates: []tls.Certificate{s.cert},
            })
            if err := tlsConn.Handshake(); err != nil {
                t.Errorf("TLS handshake failed: %v", err)
                return
            }
            
            // 更新连接和扫描器
            conn = tlsConn
            scanner = bufio.NewScanner(conn)

        case strings.HasPrefix(line, "AUTH PLAIN"):
            if _, err := fmt.Fprintf(conn, "235 2.7.0 Authentication successful\r\n"); err != nil {
                t.Errorf("Failed to send AUTH response: %v", err)
                return
            }
            return // 认证成功后返回

        case line == "QUIT":
            if _, err := fmt.Fprintf(conn, "221 2.0.0 Bye\r\n"); err != nil {
                t.Errorf("Failed to send QUIT response: %v", err)
            }
            return
        }
    }

    if err := scanner.Err(); err != nil {
        t.Errorf("Scanner error: %v", err)
    }
}

// 修改 generateTestCertificate 函数以返回一个有效的证书
func generateTestCertificate() (tls.Certificate, error) {
    // 生成私钥
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return tls.Certificate{}, err
    }

    // 创建自签名证书模板
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            CommonName: "localhost",
        },
        DNSNames:              []string{"localhost"},
        NotBefore:            time.Now(),
        NotAfter:             time.Now().Add(24 * time.Hour),
        KeyUsage:             x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    // 创建证书
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
    if err != nil {
        return tls.Certificate{}, err
    }

    // 将证书和私钥转换为PEM格式
    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: derBytes,
    })
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    })

    // 创建TLS证书
    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        return tls.Certificate{}, err
    }

    return cert, nil
}

// 更新 newMockServer 函数
func newMockServer(t *testing.T) *mockServer {
    cert, err := generateTestCertificate()
    if err != nil {
        t.Fatalf("Failed to generate test certificate: %v", err)
    }

    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("Failed to create listener: %v", err)
    }

    server := &mockServer{
        listener: listener,
        done:     make(chan struct{}),
        cert:     cert,
    }

    go server.serve(t)
    return server
}

func TestClientConnect(t *testing.T) {
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

    // 添加调试日志
    t.Logf("Connecting to %s:%d", host, portNum)

    // 设置较短的超时时间
    if err := client.Connect(); err != nil {
        t.Fatalf("Connect() error = %v", err)
    }

    if !client.isXSMTP {
        t.Error("Connect() client should be in XSMTP mode")
    }
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


func (s *mockServer) close() {
    s.listener.Close()
    <-s.done
}

// mockConn 实现完整的 net.Conn 接口
type mockConn struct {
    readData  []byte
    readIndex int
    closed    bool
}

func newMockConn() *mockConn {
    // 预设一个成功的TCP响应
    response := []byte{
        TCPStatusOK, // status
        0x00,        // message length (varint)
        0x00,        // padding length (varint)
    }
    return &mockConn{
        readData: response,
    }
}

func (m *mockConn) Read(b []byte) (n int, err error) {
    if m.closed {
        return 0, net.ErrClosed
    }
    if m.readData == nil || m.readIndex >= len(m.readData) {
        return 0, io.EOF
    }
    n = copy(b, m.readData[m.readIndex:])
    m.readIndex += n
    return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
    if m.closed {
        return 0, net.ErrClosed
    }
    return len(b), nil
}

func (m *mockConn) Close() error {
    m.closed = true
    return nil
}

func (m *mockConn) LocalAddr() net.Addr {
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockConn) RemoteAddr() net.Addr {
    return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
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

func TestClientCreateTCPProxy(t *testing.T) {
    mockConn := newMockConn()
    client := &Client{
        isXSMTP: false,
        conn:    mockConn,
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
    mockConn := newMockConn()
    client := &Client{
        isXSMTP: false,
        conn:    mockConn,
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
