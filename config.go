package xsmtp

import (
	"encoding/json"
	"errors"
	"os"
	"string"
	"fmt"
)

// config.go

// ClientConfig represents the XSMTP client configuration
type ClientConfig struct {
    Protocol   string `json:"protocol"`
    ServerIP   string `json:"server_ip"`
    ServerPort int    `json:"server_port"`
    Auth       string `json:"auth"`      // 新增字段：认证方式
    Username   string `json:"username"`
    Password   string `json:"password"`
}

// ServerConfig represents the XSMTP server configuration
type ServerConfig struct {
	Protocol          string `json:"protocol"`
	ServerIP          string `json:"server_ip"`
	ServerPort        int    `json:"server_port"`
	MasqueradeHostname string `json:"masquerade_hostname"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	UDPRelay          bool   `json:"udp_relay"`
}

// LoadClientConfig 函数也需要添加对 Auth 字段的验证
func LoadClientConfig(path string) (*ClientConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    config := &ClientConfig{}
    if err := json.Unmarshal(data, config); err != nil {
        return nil, err
    }
    
    // Validate configuration
    if config.Protocol != "xsmtp" {
        return nil, errors.New("invalid protocol, must be 'xsmtp'")
    }
    if config.ServerIP == "" {
        return nil, errors.New("server_ip is required")
    }
    if config.ServerPort <= 0 || config.ServerPort > 65535 {
        return nil, errors.New("server_port must be between 1 and 65535")
    }
    
    // 验证 Auth 字段
    config.Auth = strings.ToLower(config.Auth) // 转换为小写
    switch config.Auth {
    case "plain", "login", "cram-md5":
        // 支持的认证方式
    case "":
        config.Auth = "plain" // 默认使用 PLAIN
    default:
        return nil, fmt.Errorf("unsupported authentication method: %s", config.Auth)
    }
    
    if config.Username == "" {
        return nil, errors.New("username is required")
    }
    if config.Password == "" {
        return nil, errors.New("password is required")
    }
    
    return config, nil
}

// LoadServerConfig loads the server configuration from a JSON file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	config := &ServerConfig{
		UDPRelay: true, // Default value
	}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	
	// Validate configuration
	if config.Protocol != "xsmtp" {
		return nil, errors.New("invalid protocol, must be 'xsmtp'")
	}
	if config.ServerPort <= 0 || config.ServerPort > 65535 {
		return nil, errors.New("server_port must be between 1 and 65535")
	}
	if config.MasqueradeHostname == "" {
		return nil, errors.New("masquerade_hostname is required")
	}
	if config.Username == "" {
		return nil, errors.New("username is required")
	}
	if config.Password == "" {
		return nil, errors.New("password is required")
	}
	
	return config, nil
}
