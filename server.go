package xsmtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Server represents an XSMTP server
type Server struct {
	config      *ServerConfig
	listener    net.Listener
	udpSessions map[uint32]*udpSession
	udpMu       sync.Mutex
	tlsConfig   *tls.Config
	running     bool
	stopCh      chan struct{}
}

// udpSession represents a UDP session
type udpSession struct {
	conn      net.PacketConn
	addr      net.Addr
	lastUsed  time.Time
}

// NewServer creates a new XSMTP server with the given configuration
func NewServer(config *ServerConfig, certFile, keyFile string) (*Server, error) {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	
	return &Server{
		config:      config,
		udpSessions: make(map[uint32]*udpSession),
		tlsConfig:   tlsConfig,
		stopCh:      make(chan struct{}),
	}, nil
}

// Start starts the XSMTP server
func (s *Server) Start() error {
	if s.running {
		return errors.New("server already running")
	}
	
	addr := fmt.Sprintf("%s:%d", s.config.ServerIP, s.config.ServerPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	
	s.listener = listener
	s.running = true
	
	// Start UDP session cleanup goroutine
	go s.cleanupUDPSessions()
	
	// Accept and handle connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return // Server stopped
				default:
					log.Printf("Error accepting connection: %v", err)
					continue
				}
			}
			
			go s.handleConnection(conn)
		}
	}()
	
	log.Printf("XSMTP server started on %s", addr)
	return nil
}

// Stop stops the XSMTP server
func (s *Server) Stop() error {
	if !s.running {
		return errors.New("server not running")
	}
	
	close(s.stopCh)
	err := s.listener.Close()
	
	// Close all UDP sessions
	s.udpMu.Lock()
	for _, session := range s.udpSessions {
		session.conn.Close()
	}
	s.udpSessions = make(map[uint32]*udpSession)
	s.udpMu.Unlock()
	
	s.running = false
	return err
}

// cleanupUDPSessions periodically cleans up inactive UDP sessions
func (s *Server) cleanupUDPSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			s.udpMu.Lock()
			now := time.Now()
			for id, session := range s.udpSessions {
				// Remove sessions inactive for more than 10 minutes
				if now.Sub(session.lastUsed) > 10*time.Minute {
					session.conn.Close()
					delete(s.udpSessions, id)
				}
			}
			s.udpMu.Unlock()
			
		case <-s.stopCh:
			return
		}
	}
}

// handleConnection handles a client connection
func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()
    
    textConn := textproto.NewConn(conn)
    
    // 1. 发送初始SMTP服务就绪消息
    if err := textConn.PrintfLine("220 %s ESMTP XSMTP Proxy Ready", s.config.MasqueradeHostname); err != nil {
        log.Printf("Failed to send greeting: %v", err)
        return
    }
    
    // 2. 处理EHLO命令
    cmd, err := textConn.ReadLine()
    if err != nil {
        log.Printf("Failed to read EHLO: %v", err)
        return
    }
    if !strings.HasPrefix(strings.ToUpper(cmd), "EHLO ") {
        textConn.PrintfLine("500 Error: Expected EHLO")
        return
    }
    
    // 发送EHLO响应
    ehloResponses := []string{
        fmt.Sprintf("250-%s", s.config.MasqueradeHostname),
        "250-SIZE 20480000",
        "250-AUTH PLAIN LOGIN CRAM-MD5",
        "250-STARTTLS",
        "250 8BITMIME",
    }
    for _, resp := range ehloResponses {
        if err := textConn.PrintfLine(resp); err != nil {
            log.Printf("Failed to send EHLO response: %v", err)
            return
        }
    }
    
    // 3. 处理STARTTLS命令
    cmd, err = textConn.ReadLine()
    if err != nil {
        log.Printf("Failed to read STARTTLS: %v", err)
        return
    }
    if !strings.EqualFold(cmd, "STARTTLS") {
        textConn.PrintfLine("500 Error: Expected STARTTLS")
        return
    }
    
    if err := textConn.PrintfLine("220 2.0.0 Ready to start TLS"); err != nil {
        log.Printf("Failed to send STARTTLS response: %v", err)
        return
    }
    
    // 升级到TLS连接
    tlsConn := tls.Server(conn, s.tlsConfig)
    if err := tlsConn.Handshake(); err != nil {
        log.Printf("TLS handshake failed: %v", err)
        return
    }
    conn = tlsConn
    textConn = textproto.NewConn(tlsConn)
    
    // 4. 处理TLS后的第二次EHLO
    cmd, err = textConn.ReadLine()
    if err != nil {
        log.Printf("Failed to read second EHLO: %v", err)
        return
    }
    if !strings.HasPrefix(strings.ToUpper(cmd), "EHLO ") {
        textConn.PrintfLine("500 Error: Expected EHLO")
        return
    }
    
    // 发送第二次EHLO响应
    for _, resp := range ehloResponses {
        if err := textConn.PrintfLine(resp); err != nil {
            log.Printf("Failed to send second EHLO response: %v", err)
            return
        }
    }
    
     // 5. 处理AUTH命令
    cmd, err = textConn.ReadLine()
    if err != nil {
        log.Printf("Failed to read AUTH: %v", err)
        return
    }
    
    // 解析认证类型和参数
    authParts := strings.Fields(cmd)
    if len(authParts) < 2 || authParts[0] != "AUTH" {
        textConn.PrintfLine("500 Error: Expected AUTH command")
        return
    }

    authType := strings.ToUpper(authParts[1])
    switch authType {
    case "PLAIN":
        // 处理 PLAIN 认证
        var authData string
        if len(authParts) > 2 {
            // 认证数据包含在命令中
            authData = authParts[2]
        } else {
            // 需要等待客户端发送认证数据
            if err := textConn.PrintfLine("334 "); err != nil {
                log.Printf("Failed to send PLAIN continue: %v", err)
                return
            }
            authData, err = textConn.ReadLine()
            if err != nil {
                log.Printf("Failed to read PLAIN auth data: %v", err)
                return
            }
        }

        // 验证 PLAIN 认证
        if err := s.handlePlainAuth(textConn, authData); err != nil {
            log.Printf("PLAIN authentication failed: %v", err)
            return
        }

    case "LOGIN":
        // 处理 LOGIN 认证
        if err := s.handleLoginAuth(textConn); err != nil {
            log.Printf("LOGIN authentication failed: %v", err)
            return
        }

    case "CRAM-MD5":
        // 处理 CRAM-MD5 认证
        if err := s.handleCRAMMD5Auth(textConn); err != nil {
            log.Printf("CRAM-MD5 authentication failed: %v", err)
            return
        }

    default:
        textConn.PrintfLine("504 Unrecognized authentication type")
        return
    }
    
    // 认证成功
    if err := textConn.PrintfLine("235 2.7.0 Authentication successful"); err != nil {
        log.Printf("Failed to send AUTH success: %v", err)
        return
    }
	
    // 6. 进入XSMTP数据转发模式
    s.handleXSMTPMode(conn)
}

// handleXSMTPMode 处理XSMTP数据转发模式
func (s *Server) handleXSMTPMode(conn net.Conn) {
    for {
        // 读取消息类型
        msgType, err := ReadVarint(conn)
        if err != nil {
            if err != io.EOF {
                log.Printf("Failed to read message type: %v", err)
            }
            return
        }
        
        switch msgType {
        case TCPRequestType:
            if err := s.handleTCPRequest(conn); err != nil {
                log.Printf("Failed to handle TCP request: %v", err)
                return
            }
            
        case UDPMessageType:
            if !s.config.UDPRelay {
                // 如果UDP中继被禁用，则静默丢弃UDP消息
                continue
            }
            if err := s.handleUDPMessage(conn); err != nil {
                log.Printf("Failed to handle UDP message: %v", err)
                return
            }
            
        default:
            log.Printf("Unknown message type: %d", msgType)
            return
        }
    }
}

// handleTCPRequest 处理TCP代理请求
func (s *Server) handleTCPRequest(conn net.Conn) error {
    // 读取TCP请求
    address, _, err := ReadTCPRequest(conn)
    if err != nil {
        WriteTCPResponse(conn, TCPStatusError, err.Error(), nil)
        return err
    }
    
    // 建立到目标的连接
    target, err := net.Dial("tcp", address)
    if err != nil {
        WriteTCPResponse(conn, TCPStatusError, err.Error(), nil)
        return err
    }
    defer target.Close()
    
    // 发送成功响应
    if err := WriteTCPResponse(conn, TCPStatusOK, "", nil); err != nil {
        return err
    }
    
    // 开始双向数据转发
    errCh := make(chan error, 2)
    go func() {
        _, err := io.Copy(target, conn)
        errCh <- err
    }()
    go func() {
        _, err := io.Copy(conn, target)
        errCh <- err
    }()
    
    // 等待任一方向完成
    err = <-errCh
    if err != nil && err != io.EOF {
        return err
    }
    return nil
}

// handleUDPMessage 处理UDP消息
func (s *Server) handleUDPMessage(conn net.Conn) error {
    // 读取UDP消息
    sessionID, _, _, _, address, payload, err := ReadUDPMessage(conn)
    if err != nil {
        return err
    }
    
    // 如果UDP中继被禁用，则直接返回
    if !s.config.UDPRelay {
        return nil
    }
    
    // 获取或创建UDP会话
    s.udpMu.Lock()
    session, exists := s.udpSessions[sessionID]
    if !exists {
        // 创建新的UDP连接
        udpConn, err := net.ListenPacket("udp", "")
        if err != nil {
            s.udpMu.Unlock()
            return fmt.Errorf("failed to create UDP socket: %w", err)
        }
        
        session = &udpSession{
            conn:     udpConn,
            lastUsed: time.Now(),
        }
        s.udpSessions[sessionID] = session
        
        // 启动UDP响应接收协程
        go s.handleUDPResponses(sessionID, session, conn)
    }
    session.lastUsed = time.Now()
    s.udpMu.Unlock()
    
    // 解析目标地址
    targetAddr, err := net.ResolveUDPAddr("udp", address)
    if err != nil {
        return fmt.Errorf("failed to resolve UDP address %s: %w", address, err)
    }
    
    // 发送数据
    _, err = session.conn.WriteTo(payload, targetAddr)
    if err != nil {
        return fmt.Errorf("failed to write UDP data: %w", err)
    }
    
    return nil
}

// handleUDPResponses 处理UDP响应
func (s *Server) handleUDPResponses(sessionID uint32, session *udpSession, clientConn net.Conn) {
    buffer := make([]byte, 65507) // 最大UDP包大小
    packetID := uint16(0)
    
    for {
        // 读取UDP响应
        n, remoteAddr, err := session.conn.ReadFrom(buffer)
        if err != nil {
            log.Printf("Failed to read UDP response: %v", err)
            return
        }
        
        // 发送UDP消息到客户端
        err = WriteUDPMessage(clientConn, sessionID, packetID, 0, 1,
            remoteAddr.String(), buffer[:n])
        if err != nil {
            log.Printf("Failed to write UDP response: %v", err)
            return
        }
        
        packetID++
    }
}

// forceCleanupUDPSessions forces cleanup of inactive UDP sessions (for testing)
func (s *Server) forceCleanupUDPSessions() {
    s.udpMu.Lock()
    now := time.Now()
    for id, session := range s.udpSessions {
        if now.Sub(session.lastUsed) > 10*time.Minute {
            session.conn.Close()
            delete(s.udpSessions, id)
        }
    }
    s.udpMu.Unlock()
}
