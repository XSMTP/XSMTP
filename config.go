package xsmtp

import (
	"encoding/json"
	"errors"
	"os"
)

// ClientConfig represents the XSMTP client configuration
type ClientConfig struct {
	Protocol   string `json:"protocol"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
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

// LoadClientConfig loads the client configuration from a JSON file
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
