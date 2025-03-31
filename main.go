package xsmtp

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "sync"
    "syscall"
)

var Version = "dev"

// 程序状态
type programState struct {
    server *Server
    client *Client
    wg     sync.WaitGroup
}

// 启动服务端
func (ps *programState) startServer(configPath, certFile, keyFile string) error {
    config, err := LoadServerConfig(configPath)
    if err != nil {
        return fmt.Errorf("failed to load server config: %v", err)
    }

    server, err := NewServer(config, certFile, keyFile)
    if err != nil {
        return fmt.Errorf("failed to create server: %v", err)
    }

    ps.server = server
    ps.wg.Add(1)
    go func() {
        defer ps.wg.Done()
        log.Printf("Starting XSMTP server v%s on %s:%d", Version, config.ServerIP, config.ServerPort)
        if err := server.Start(); err != nil {
            log.Printf("Server error: %v", err)
        }
    }()

    return nil
}

// 启动客户端
func (ps *programState) startClient(configPath string) error {
    config, err := LoadClientConfig(configPath)
    if err != nil {
        return fmt.Errorf("failed to load client config: %v", err)
    }

    client := NewClient(config)
    ps.client = client
    ps.wg.Add(1)
    go func() {
        defer ps.wg.Done()
        log.Printf("Starting XSMTP client v%s, connecting to %s:%d", Version, config.ServerIP, config.ServerPort)
        if err := client.Connect(); err != nil {
            log.Printf("Client error: %v", err)
            return
        }
        // 保持客户端运行
        select {}
    }()

    return nil
}

// 关闭所有服务
func (ps *programState) shutdown() {
    if ps.client != nil {
        if err := ps.client.Close(); err != nil {
            log.Printf("Error closing client: %v", err)
        }
    }
    if ps.server != nil {
        if err := ps.server.Stop(); err != nil {
            log.Printf("Error stopping server: %v", err)
        }
    }
    ps.wg.Wait()
}

func Main() {
    // 解析命令行参数
    var showVersion bool
    flag.BoolVar(&showVersion, "version", false, "Show version information")
    flag.Parse()

    // 显示版本信息
    if showVersion {
        fmt.Printf("XSMTP %s\n", Version)
        os.Exit(0)
    }

    // 获取可执行文件所在目录
    execPath, err := os.Executable()
    if err != nil {
        log.Fatalf("Failed to get executable path: %v", err)
    }
    execDir := filepath.Dir(execPath)

    // 检查配置文件
    serverConfigPath := filepath.Join(execDir, "server-config.json")
    clientConfigPath := filepath.Join(execDir, "client-config.json")
    certFile := filepath.Join(execDir, "cert.pem")
    keyFile := filepath.Join(execDir, "key.pem")

    hasServerConfig := false
    hasClientConfig := false

    if _, err := os.Stat(serverConfigPath); err == nil {
        hasServerConfig = true
    }
    if _, err := os.Stat(clientConfigPath); err == nil {
        hasClientConfig = true
    }

    if !hasServerConfig && !hasClientConfig {
        log.Fatal("No configuration files found. Please create either server-config.json or client-config.json")
    }

    // 创建程序状态实例
    ps := &programState{}

    // 启动服务
    if hasServerConfig {
        // 检查证书文件
        if _, err := os.Stat(certFile); os.IsNotExist(err) {
            log.Fatal("Certificate file (cert.pem) not found")
        }
        if _, err := os.Stat(keyFile); os.IsNotExist(err) {
            log.Fatal("Private key file (key.pem) not found")
        }

        if err := ps.startServer(serverConfigPath, certFile, keyFile); err != nil {
            log.Printf("Failed to start server: %v", err)
        }
    }

    if hasClientConfig {
        if err := ps.startClient(clientConfigPath); err != nil {
            log.Printf("Failed to start client: %v", err)
        }
    }

    // 设置信号处理
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    // 等待中断信号
    <-sigChan
    log.Println("Shutting down...")
    ps.shutdown()
    log.Println("Shutdown complete")
}
