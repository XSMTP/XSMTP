package xsmtp

import (
	"crypto/hmac"
        "crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Client represents an XSMTP client
type Client struct {
    config     *ClientConfig
    conn       net.Conn
    textConn   *textproto.Conn  // 修复拼写错误：textprto -> textproto
    udpCounter uint32
    mu         sync.Mutex
    isXSMTP    bool // Flag to indicate if we've switched to XSMTP mode
    ehloResp   string // 存储最后一次EHLO响应
}

// NewClient creates a new XSMTP client with the given configuration
func NewClient(config *ClientConfig) *Client {
    return &Client{
        config:     config,
        udpCounter: 0,
        isXSMTP:    false,
    }
}

// ehlo sends an EHLO command to the server
func (c *Client) ehlo() error {
    id, err := c.textConn.Cmd("EHLO localhost")
    if err != nil {
        return err
    }
    c.textConn.StartResponse(id)
    _, msg, err := c.textConn.ReadResponse(250)
    c.textConn.EndResponse(id)
    if err != nil {
        return err
    }
    // 存储EHLO响应
    c.ehloResp = msg
    return nil
}

// hasExtension checks if the server supports a specific extension
func (c *Client) hasExtension(ext string) bool {
    if c.ehloResp == "" {
        return false
    }
    
    for _, line := range strings.Split(c.ehloResp, "\n") {
        if strings.HasPrefix(line, "250-"+ext) || strings.HasPrefix(line, "250 "+ext) {
            return true
        }
    }
    return false
}

// authPlain performs PLAIN authentication
func (c *Client) authPlain() error {
    auth := base64.StdEncoding.EncodeToString([]byte("\x00"+c.config.Username+"\x00"+c.config.Password))
    id, err := c.textConn.Cmd("AUTH PLAIN %s", auth)
    if err != nil {
        return fmt.Errorf("failed to send AUTH PLAIN command: %w", err)
    }
    c.textConn.StartResponse(id)
    code, _, err := c.textConn.ReadResponse(235)
    c.textConn.EndResponse(id)
    if err != nil || code != 235 {
        return fmt.Errorf("AUTH PLAIN failed: %w", err)
    }
    return nil
}

// authLogin performs LOGIN authentication
func (c *Client) authLogin() error {
    // Send AUTH LOGIN command
    id, err := c.textConn.Cmd("AUTH LOGIN")
    if err != nil {
        return fmt.Errorf("failed to send AUTH LOGIN command: %w", err)
    }
    c.textConn.StartResponse(id)
    code, _, err := c.textConn.ReadResponse(334)
    c.textConn.EndResponse(id)
    if err != nil || code != 334 {
        return fmt.Errorf("AUTH LOGIN failed at step 1: %w", err)
    }

    // Send username
    id, err = c.textConn.Cmd(base64.StdEncoding.EncodeToString([]byte(c.config.Username)))
    if err != nil {
        return fmt.Errorf("failed to send username: %w", err)
    }
    c.textConn.StartResponse(id)
    code, _, err = c.textConn.ReadResponse(334)
    c.textConn.EndResponse(id)
    if err != nil || code != 334 {
        return fmt.Errorf("AUTH LOGIN failed at step 2: %w", err)
    }

    // Send password
    id, err = c.textConn.Cmd(base64.StdEncoding.EncodeToString([]byte(c.config.Password)))
    if err != nil {
        return fmt.Errorf("failed to send password: %w", err)
    }
    c.textConn.StartResponse(id)
    code, _, err = c.textConn.ReadResponse(235)
    c.textConn.EndResponse(id)
    if err != nil || code != 235 {
        return fmt.Errorf("AUTH LOGIN failed at step 3: %w", err)
    }

    return nil
}

// computeCRAMMD5 calculates the CRAM-MD5 response
func (c *Client) computeCRAMMD5(challenge, username, password string) string {
    h := hmac.New(md5.New, []byte(password))
    h.Write([]byte(challenge))
    digest := fmt.Sprintf("%x", h.Sum(nil))
    return fmt.Sprintf("%s %s", username, digest)
}

// authCRAMMD5 performs CRAM-MD5 authentication
func (c *Client) authCRAMMD5() error {
    // Send AUTH CRAM-MD5 command
    id, err := c.textConn.Cmd("AUTH CRAM-MD5")
    if err != nil {
        return fmt.Errorf("failed to send AUTH CRAM-MD5 command: %w", err)
    }
    c.textConn.StartResponse(id)
    code, msg, err := c.textConn.ReadResponse(334)
    c.textConn.EndResponse(id)
    if err != nil || code != 334 {
        return fmt.Errorf("AUTH CRAM-MD5 failed at step 1: %w", err)
    }

    // Decode challenge
    challenge, err := base64.StdEncoding.DecodeString(msg)
    if err != nil {
        return fmt.Errorf("failed to decode CRAM-MD5 challenge: %w", err)
    }

    // Calculate response
    response := c.computeCRAMMD5(string(challenge), c.config.Username, c.config.Password)
    
    // Send response
    id, err = c.textConn.Cmd(base64.StdEncoding.EncodeToString([]byte(response)))
    if err != nil {
        return fmt.Errorf("failed to send CRAM-MD5 response: %w", err)
    }
    c.textConn.StartResponse(id)
    code, _, err = c.textConn.ReadResponse(235)
    c.textConn.EndResponse(id)
    if err != nil || code != 235 {
        return fmt.Errorf("AUTH CRAM-MD5 failed at step 2: %w", err)
    }

    return nil
}

// Connect connects to the XSMTP server, performs the SMTP handshake,
// and authenticates using the provided credentials
func (c *Client) Connect() error {
    // Connect to the server
    addr := fmt.Sprintf("%s:%d", c.config.ServerIP, c.config.ServerPort)
    conn, err := net.Dial("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to connect to server: %w", err)
    }
    c.conn = conn
    c.textConn = textproto.NewConn(conn)
    
    // Read the initial greeting
    code, msg, err := c.textConn.ReadResponse(220)
    if err != nil {
        c.conn.Close()
        return fmt.Errorf("failed to read server greeting: %w", err)
    }
    if code != 220 {
        c.conn.Close()
        return fmt.Errorf("unexpected server greeting: %d %s", code, msg)
    }
    
    // Send EHLO and store extensions
    if err := c.ehlo(); err != nil {
        c.conn.Close()
        return fmt.Errorf("EHLO failed: %w", err)
    }
    
    // Check if STARTTLS is supported
    if !c.hasExtension("STARTTLS") {
        c.conn.Close()
        return errors.New("server does not support STARTTLS")
    }
    
    // Send STARTTLS
    id, err := c.textConn.Cmd("STARTTLS")
    if err != nil {
        c.conn.Close()
        return fmt.Errorf("failed to send STARTTLS command: %w", err)
    }
    c.textConn.StartResponse(id)
    code, msg, err = c.textConn.ReadResponse(220)
    c.textConn.EndResponse(id)
    if err != nil {
        c.conn.Close()
        return fmt.Errorf("STARTTLS failed: %w", err)
    }
    
    // Upgrade connection to TLS
    tlsConn := tls.Client(c.conn, &tls.Config{
        ServerName:         c.config.ServerIP,
        InsecureSkipVerify: true, // 添加此选项用于测试
        MinVersion:        tls.VersionTLS12,
    })
    if err := tlsConn.Handshake(); err != nil {
        c.conn.Close()
        return fmt.Errorf("TLS handshake failed: %w", err)
    }
    c.conn = tlsConn
    c.textConn = textproto.NewConn(tlsConn)
    
    // Send EHLO again over TLS and store new extensions
    if err := c.ehlo(); err != nil {
        c.conn.Close()
        return fmt.Errorf("EHLO after STARTTLS failed: %w", err)
    }
    
    // Check if AUTH is supported
    if !c.hasExtension("AUTH") {
        c.conn.Close()
        return errors.New("server does not support AUTH")
    }

    // 检查服务器是否支持指定的认证方式
    authMethod := strings.ToUpper(c.config.Auth)
    if !c.hasExtension("AUTH " + authMethod) {
        c.conn.Close()
        return fmt.Errorf("server does not support %s authentication", authMethod)
    }
    
    // 根据配置的认证方式进行认证
    var authErr error
    switch strings.ToLower(c.config.Auth) {
    case "plain":
        authErr = c.authPlain()
    case "login":
        authErr = c.authLogin()
    case "cram-md5":
        authErr = c.authCRAMMD5()
    default:
        c.conn.Close()
        return fmt.Errorf("unsupported authentication method: %s", c.config.Auth)
    }

    if authErr != nil {
        c.conn.Close()
        return fmt.Errorf("authentication failed: %w", authErr)
    }
    
    // Now we're authenticated and in XSMTP Data Forwarding Mode
    c.isXSMTP = true
    return nil
}

// CreateTCPProxy creates a TCP proxy connection to the specified address
func (c *Client) CreateTCPProxy(address string) (net.Conn, error) {
	if !c.isXSMTP {
		return nil, errors.New("not in XSMTP mode, call Connect() first")
	}
	
	// Send TCP request
	if err := WriteTCPRequest(c.conn, address, nil); err != nil {
		return nil, fmt.Errorf("failed to write TCP request: %w", err)
	}
	
	// Read response
	status, message, _, err := ReadTCPResponse(c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCP response: %w", err)
	}
	
	if status != TCPStatusOK {
		return nil, fmt.Errorf("proxy connection failed: %s", message)
	}
	
	// Create a proxy connection
	return &proxyConn{
		client: c,
		addr:   address,
	}, nil
}

// SendUDP sends a UDP packet to the specified address
func (c *Client) SendUDP(sessionID uint32, address string, data []byte) error {
	if !c.isXSMTP {
		return errors.New("not in XSMTP mode, call Connect() first")
	}
	
	c.mu.Lock()
	packetID := uint16(c.udpCounter % 65536)
	c.udpCounter++
	c.mu.Unlock()
	
	// Simple implementation without fragmentation
	return WriteUDPMessage(c.conn, sessionID, packetID, 0, 1, address, data)
}

// Close closes the connection to the server
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// proxyConn implements net.Conn for a TCP proxy connection
type proxyConn struct {
	client *Client
	addr   string
	
	readBuf []byte
	offset  int
	closed  bool
	mu      sync.Mutex
}

// Read reads data from the proxy connection
func (p *proxyConn) Read(b []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return 0, net.ErrClosed
	}
	
	// If we have data in the buffer, copy it to b
	if p.readBuf != nil && p.offset < len(p.readBuf) {
		n = copy(b, p.readBuf[p.offset:])
		p.offset += n
		if p.offset >= len(p.readBuf) {
			p.readBuf = nil
			p.offset = 0
		}
		return n, nil
	}
	
	// Read directly from the underlying connection
	return p.client.conn.Read(b)
}

// Write writes data to the proxy connection
func (p *proxyConn) Write(b []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return 0, net.ErrClosed
	}
	
	return p.client.conn.Write(b)
}

// Close closes the proxy connection
func (p *proxyConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return net.ErrClosed
	}
	
	p.closed = true
	return nil
}

// LocalAddr returns the local network address
func (p *proxyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns the remote network address
func (p *proxyConn) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(p.addr)
	portNum, _ := net.LookupPort("tcp", port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: portNum}
}

// SetDeadline sets the read and write deadlines
func (p *proxyConn) SetDeadline(t time.Time) error {
	return p.client.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (p *proxyConn) SetReadDeadline(t time.Time) error {
	return p.client.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (p *proxyConn) SetWriteDeadline(t time.Time) error {
	return p.client.conn.SetWriteDeadline(t)
}
