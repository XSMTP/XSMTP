package xsmtp

import (
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
	textConn   *textproto.Conn
	udpCounter uint32
	mu         sync.Mutex
	isXSMTP    bool // Flag to indicate if we've switched to XSMTP mode
}

// NewClient creates a new XSMTP client with the given configuration
func NewClient(config *ClientConfig) *Client {
    return &Client{
        config:     config,
        udpCounter: 0,
        isXSMTP:    false,
        extensions: make(map[string]string),
    }
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
	
	// Send EHLO
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
		ServerName: c.config.ServerIP,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		c.conn.Close()
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	c.conn = tlsConn
	c.textConn = textproto.NewConn(tlsConn)
	
	// Send EHLO again over TLS
	if err := c.ehlo(); err != nil {
		c.conn.Close()
		return fmt.Errorf("EHLO after STARTTLS failed: %w", err)
	}
	
	// Check if AUTH is supported
	if !c.hasExtension("AUTH") {
		c.conn.Close()
		return errors.New("server does not support AUTH")
	}
	
	// Authenticate using PLAIN
	id, err = c.textConn.Cmd("AUTH PLAIN %s", 
		base64.StdEncoding.EncodeToString([]byte("\x00"+c.config.Username+"\x00"+c.config.Password)))
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to send AUTH command: %w", err)
	}
	c.textConn.StartResponse(id)
	code, msg, err = c.textConn.ReadResponse(235)
	c.textConn.EndResponse(id)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	// Now we're authenticated and in XSMTP Data Forwarding Mode
	c.isXSMTP = true
	return nil
}

// ehlo sends an EHLO command to the server and stores the extensions
func (c *Client) ehlo() error {
    id, err := c.textConn.Cmd("EHLO localhost")
    if err != nil {
        return err
    }
    
    c.textConn.StartResponse(id)
    defer c.textConn.EndResponse(id)
    
    code, msg, err := c.textConn.ReadResponse(250)
    if err != nil {
        return err
    }
    
    // 清除旧的扩展
    c.extensions = make(map[string]string)
    
    // 解析并存储扩展
    for _, line := range strings.Split(msg, "\n") {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }
        
        // 移除前缀
        if strings.HasPrefix(line, "250-") {
            line = line[4:]
        } else if strings.HasPrefix(line, "250 ") {
            line = line[4:]
        } else {
            continue
        }
        
        // 分割扩展名和参数
        parts := strings.SplitN(line, " ", 2)
        if len(parts) == 1 {
            c.extensions[parts[0]] = ""
        } else {
            c.extensions[parts[0]] = parts[1]
        }
    }
    
    return nil
}

// hasExtension checks if the server supports a specific extension
func (c *Client) hasExtension(ext string) bool {
    _, exists := c.extensions[ext]
    return exists
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
    
    // Authenticate using PLAIN
    auth := base64.StdEncoding.EncodeToString([]byte("\x00"+c.config.Username+"\x00"+c.config.Password))
    id, err = c.textConn.Cmd("AUTH PLAIN %s", auth)
    if err != nil {
        c.conn.Close()
        return fmt.Errorf("failed to send AUTH command: %w", err)
    }
    c.textConn.StartResponse(id)
    code, msg, err = c.textConn.ReadResponse(235)
    c.textConn.EndResponse(id)
    if err != nil {
        c.conn.Close()
        return fmt.Errorf("authentication failed: %w", err)
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
