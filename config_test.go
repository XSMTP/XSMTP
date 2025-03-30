package xsmtp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "Valid config",
			config: `{
				"protocol": "xsmtp",
				"server_ip": "127.0.0.1",
				"server_port": 587,
				"username": "test",
				"password": "test123"
			}`,
			wantErr: false,
		},
		{
			name: "Invalid protocol",
			config: `{
				"protocol": "smtp",
				"server_ip": "127.0.0.1",
				"server_port": 587,
				"username": "test",
				"password": "test123"
			}`,
			wantErr: true,
		},
		{
			name: "Missing required fields",
			config: `{
				"protocol": "xsmtp",
				"server_port": 587
			}`,
			wantErr: true,
		},
		{
			name: "Invalid port",
			config: `{
				"protocol": "xsmtp",
				"server_ip": "127.0.0.1",
				"server_port": 0,
				"username": "test",
				"password": "test123"
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpfile := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(tmpfile, []byte(tt.config), 0644); err != nil {
				t.Fatal(err)
			}

			// Test loading config
			_, err := LoadClientConfig(tmpfile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadClientConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadServerConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "Valid config",
			config: `{
				"protocol": "xsmtp",
				"server_ip": "0.0.0.0",
				"server_port": 587,
				"masquerade_hostname": "smtp.gmail.com",
				"username": "test",
				"password": "test123",
				"udp_relay": true
			}`,
			wantErr: false,
		},
		{
			name: "Invalid protocol",
			config: `{
				"protocol": "smtp",
				"server_ip": "0.0.0.0",
				"server_port": 587,
				"masquerade_hostname": "smtp.gmail.com",
				"username": "test",
				"password": "test123"
			}`,
			wantErr: true,
		},
		{
			name: "Missing required fields",
			config: `{
				"protocol": "xsmtp",
				"server_port": 587
			}`,
			wantErr: true,
		},
		{
			name: "Invalid port",
			config: `{
				"protocol": "xsmtp",
				"server_ip": "0.0.0.0",
				"server_port": 0,
				"masquerade_hostname": "smtp.gmail.com",
				"username": "test",
				"password": "test123"
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpfile := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(tmpfile, []byte(tt.config), 0644); err != nil {
				t.Fatal(err)
			}

			// Test loading config
			_, err := LoadServerConfig(tmpfile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadServerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
