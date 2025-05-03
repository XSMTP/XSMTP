package xsmtp

import (
    "encoding/base64"
    "time"
    "errors"
    "fmt"
    "net/textproto"
    "strings"
    "crypto/hmac"
    "crypto/md5"
    "os"
)

// 处理 PLAIN 认证
func (s *Server) handlePlainAuth(textConn *textproto.Conn, authData string) error {
    decoded, err := base64.StdEncoding.DecodeString(authData)
    if err != nil {
        textConn.PrintfLine("501 5.5.4 Syntax error in parameters")
        return fmt.Errorf("failed to decode PLAIN auth data: %w", err)
    }
    
    parts := strings.Split(string(decoded), "\x00")
    if len(parts) != 3 || parts[1] != s.config.Username || parts[2] != s.config.Password {
        textConn.PrintfLine("535 5.7.8 Authentication credentials invalid")
        return errors.New("invalid credentials")
    }
    
    return nil
}

// 处理 LOGIN 认证
func (s *Server) handleLoginAuth(textConn *textproto.Conn) error {
    // 请求用户名
    usernamePrompt := base64.StdEncoding.EncodeToString([]byte("Username:"))
    if err := textConn.PrintfLine("334 %s", usernamePrompt); err != nil {
        return fmt.Errorf("failed to send username prompt: %w", err)
    }
    
    userResp, err := textConn.ReadLine()
    if err != nil {
        return fmt.Errorf("failed to read username: %w", err)
    }
    
    username, err := base64.StdEncoding.DecodeString(userResp)
    if err != nil {
        textConn.PrintfLine("501 5.5.4 Syntax error in parameters")
        return fmt.Errorf("failed to decode username: %w", err)
    }
    
    // 请求密码
    passwordPrompt := base64.StdEncoding.EncodeToString([]byte("Password:"))
    if err := textConn.PrintfLine("334 %s", passwordPrompt); err != nil {
        return fmt.Errorf("failed to send password prompt: %w", err)
    }
    
    passResp, err := textConn.ReadLine()
    if err != nil {
        return fmt.Errorf("failed to read password: %w", err)
    }
    
    password, err := base64.StdEncoding.DecodeString(passResp)
    if err != nil {
        textConn.PrintfLine("501 5.5.4 Syntax error in parameters")
        return fmt.Errorf("failed to decode password: %w", err)
    }
    
    // 验证凭证
    if string(username) != s.config.Username || string(password) != s.config.Password {
        textConn.PrintfLine("535 5.7.8 Authentication credentials invalid")
        return errors.New("invalid credentials")
    }
    
    return nil
}

// 处理 CRAM-MD5 认证
func (s *Server) handleCRAMMD5Auth(textConn *textproto.Conn) error {
    // 生成挑战字符串
    challenge := fmt.Sprintf("<%d.%d@%s>", time.Now().UnixNano(), os.Getpid(), s.config.MasqueradeHostname)
    
    // 发送挑战
    challengeB64 := base64.StdEncoding.EncodeToString([]byte(challenge))
    if err := textConn.PrintfLine("334 %s", challengeB64); err != nil {
        return fmt.Errorf("failed to send challenge: %w", err)
    }
    
    // 读取响应
    resp, err := textConn.ReadLine()
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }
    
    // 解码响应
    decoded, err := base64.StdEncoding.DecodeString(resp)
    if err != nil {
        textConn.PrintfLine("501 5.5.4 Syntax error in parameters")
        return fmt.Errorf("failed to decode response: %w", err)
    }
    
    // 验证响应
    parts := strings.Split(string(decoded), " ")
    if len(parts) != 2 {
        textConn.PrintfLine("535 5.7.8 Authentication credentials invalid")
        return errors.New("invalid response format")
    }
    
    username := parts[0]
    responseDigest := parts[1]
    
    // 计算预期的摘要
    expectedDigest := computeCRAMMD5(challenge, s.config.Password)
    
    // 验证用户名和摘要
    if username != s.config.Username || responseDigest != expectedDigest {
        textConn.PrintfLine("535 5.7.8 Authentication credentials invalid")
        return errors.New("invalid credentials")
    }
    
    return nil
}

// 计算 CRAM-MD5 摘要
func computeCRAMMD5(challenge, password string) string {
    h := hmac.New(md5.New, []byte(password))
    h.Write([]byte(challenge))
    return fmt.Sprintf("%x", h.Sum(nil))
}
