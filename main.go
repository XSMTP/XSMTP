package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "path/filepath"
)

var Version = "dev"

// configType 用于判断配置类型
type configType struct {
    // 服务端特有字段
    MasqueradeHostname string `json:"masquerade_hostname,omitempty"`
    // 两者共有字段
    Protocol   string `json:"protocol"`
    ServerIP   string `json:"server_ip"`
    ServerPort int    `json:"server_port"`
    Username   string `json:"username"`
    Password   string `json:"password"`
}

func main() {
    // 解析命令行参数
    var (
        showVersion bool
        configFile  string
        certFile   string
        keyFile    string
    )

    flag.BoolVar(&showVersion, "version", false, "Show version information")
    flag.StringVar(&configFile, "config", "config.json", "Path to config file")
    flag.StringVar(&certFile, "cert", "cert.pem", "Path to TLS certificate file (server only)")
    flag.StringVar(&keyFile, "key", "key.pem", "Path to TLS private key file (server only)")
    flag.Parse()

    // 显示版本信息
    if showVersion {
        fmt.Printf("XSMTP %s\n", Version)
        os.Exit(0)
    }

    // 读取配置文件
    data, err := os.ReadFile(configFile)
    if err != nil {
        log.Fatalf("Failed to read config file: %v", err)
    }

    // 首先解析基本结构以判断类型
    var basicConfig configType
    if err := json.Unmarshal(data, &basicConfig); err != nil {
        log.Fatalf("Failed to parse config file: %v", err)
    }

    // 根据配置判断运行模式
    isServer := basicConfig.MasqueradeHostname != ""

    if isServer {
        // 服务端模式
        config, err := xsmtp.LoadServerConfig(configFile)
        if err != nil {
            log.Fatalf("Failed to load server config: %v", err)
        }

        // 检查证书文件
        if _, err := os.Stat(certFile); os.IsNotExist(err) {
            log.Fatalf("Certificate file not found: %s", certFile)
        }
        if _, err := os.Stat(keyFile); os.IsNotExist(err) {
            log.Fatalf("Private key file not found: %s", keyFile)
        }

        server, err := xsmtp.NewServer(config, certFile, keyFile)
        if err != nil {
            log.Fatalf("Failed to create server: %v", err)
        }

        log.Printf("Starting XSMTP server v%s on %s:%d", Version, config.ServerIP, config.ServerPort)
        if err := server.Start(); err != nil {
            log.Fatalf("Server error: %v", err)
        }
    } else {
        // 客户端模式
        config, err := xsmtp.LoadClientConfig(configFile)
        if err != nil {
            log.Fatalf("Failed to load client config: %v", err)
        }

        client := xsmtp.NewClient(config)
        log.Printf("Starting XSMTP client v%s, connecting to %s:%d", Version, config.ServerIP, config.ServerPort)
        
        if err := client.Connect(); err != nil {
            log.Fatalf("Failed to connect: %v", err)
        }
        defer client.Close()

        // 保持客户端运行直到收到中断信号
        c := make(chan os.Signal, 1)
        signal.Notify(c, os.Interrupt, syscall.SIGTERM)
        <-c
        log.Println("Shutting down client...")
    }
}
