package xsmtp

import (
	"crypto/tls"
	"encoding/base64"
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
func
