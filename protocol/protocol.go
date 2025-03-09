// protocol/protocol.go
package protocol

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SMTPCommand 表示解析后的 SMTP 命令
type SMTPCommand struct {
	Verb        string
	Args        string
	FullCommand string // 原始命令字符串，用于调试
}

// ParseSMTPCommand 解析 SMTP 命令字符串
func ParseSMTPCommand(line string) (*SMTPCommand, error) {
	line = strings.TrimSuffix(line, "\r\n") // 移除 CRLF
	parts := strings.SplitN(line, " ", 2)
	verb := strings.ToUpper(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	return &SMTPCommand{
		Verb:        verb,
		Args:        args,
		FullCommand: line,
	}, nil
}

// AuthPlainInfo 表示 AUTH PLAIN 认证信息
type AuthPlainInfo struct {
	AuthorizationIdentity string
	Username            string
	Password            string
}

// ParseAuthPlainInfo 解析 AUTH PLAIN 命令的 Base64 编码信息
func ParseAuthPlainInfo(base64Line string) (*AuthPlainInfo, error) {
	base64Line = strings.TrimSuffix(base64Line, "\r\n")
	encodedAuthInfo := strings.TrimSpace(strings.TrimPrefix(base64Line, "AUTH PLAIN")) // 移除 "AUTH PLAIN " 前缀，并 trim 空格
	if encodedAuthInfo == "" {
		encodedAuthInfo = strings.TrimSpace(base64Line) // 如果只有 "AUTH PLAIN\r\n"
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(encodedAuthInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 AUTH info: %w", err)
	}
	decodedStr := string(decodedBytes)
	parts := strings.SplitN(decodedStr, "\x00", 3) // 使用 null 字节分割

	authInfo := &AuthPlainInfo{}
	if len(parts) >= 3 {
		authInfo.AuthorizationIdentity = parts[0]
		authInfo.Username = parts[1]
		authInfo.Password = parts[2]
	} else if len(parts) == 2 {
		authInfo.Username = parts[0]
		authInfo.Password = parts[1]
	} else if len(parts) == 1 {
		authInfo.Username = parts[0] // 某些客户端可能只发送用户名和密码，没有 Authorization Identity
	} else {
		return nil, fmt.Errorf("invalid AUTH PLAIN info format")
	}

	return authInfo, nil
}


// TCPRequest 封装 TCP 代理请求消息
type TCPRequest struct {
	Address string
	Padding []byte // 可选填充
}

// UDPMessage 封装 UDP 代理消息
type UDPMessage struct {
	SessionID     uint32
	PacketID      uint16
	FragmentID    uint8
	FragmentCount uint8
	Address       string
	Payload       []byte
}


// MessageType 定义消息类型
type MessageType uint8

const (
	MessageTypeTCPRequest MessageType = 0x01
	MessageTypeUDPMessage MessageType = 0x02
)


// ParseMessageTypeFromByte 从字节解析消息类型
func ParseMessageTypeFromByte(b byte) (MessageType, error) {
	messageType := MessageType(b)
	switch messageType {
	case MessageTypeTCPRequest, MessageTypeUDPMessage:
		return messageType, nil
	default:
		return 0, fmt.Errorf("unknown message type: 0x%x", b)
	}
}
