package xsmtp

import (
	"bytes"
	"testing"
)

func TestWriteAndReadVarint(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
	}{
		{"6-bit", 42},
		{"14-bit", 16383},
		{"30-bit", 1073741823},
		{"62-bit", 4611686018427387903},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			
			// Write varint
			if err := WriteVarint(buf, tt.value); err != nil {
				t.Errorf("WriteVarint() error = %v", err)
				return
			}
			
			// Read varint
			got, err := ReadVarint(buf)
			if err != nil {
				t.Errorf("ReadVarint() error = %v", err)
				return
			}
			
			if got != tt.value {
				t.Errorf("ReadVarint() = %v, want %v", got, tt.value)
			}
		})
	}
}

func TestWriteAndReadTCPRequest(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		padding  []byte
		wantErr  bool
	}{
		{
			name:    "Simple request",
			address: "google.com:80",
			padding: nil,
		},
		{
			name:    "With padding",
			address: "example.com:443",
			padding: []byte("random padding"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			
			// Write request
			err := WriteTCPRequest(buf, tt.address, tt.padding)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr {
				return
			}
			
			// Read request
			gotAddr, gotPad, err := ReadTCPRequest(buf)
			if err != nil {
				t.Errorf("ReadTCPRequest() error = %v", err)
				return
			}
			
			if gotAddr != tt.address {
				t.Errorf("ReadTCPRequest() address = %v, want %v", gotAddr, tt.address)
			}
			
			if !bytes.Equal(gotPad, tt.padding) {
				t.Errorf("ReadTCPRequest() padding = %v, want %v", gotPad, tt.padding)
			}
		})
	}
}

func TestWriteAndReadTCPResponse(t *testing.T) {
	tests := []struct {
		name     string
		status   byte
		message  string
		padding  []byte
		wantErr  bool
	}{
		{
			name:    "Success response",
			status:  TCPStatusOK,
			message: "",
			padding: nil,
		},
		{
			name:    "Error response",
			status:  TCPStatusError,
			message: "Connection failed",
			padding: []byte("random padding"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			
			// Write response
			err := WriteTCPResponse(buf, tt.status, tt.message, tt.padding)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr {
				return
			}
			
			// Read response
			gotStatus, gotMsg, gotPad, err := ReadTCPResponse(buf)
			if err != nil {
				t.Errorf("ReadTCPResponse() error = %v", err)
				return
			}
			
			if gotStatus != tt.status {
				t.Errorf("ReadTCPResponse() status = %v, want %v", gotStatus, tt.status)
			}
			
			if gotMsg != tt.message {
				t.Errorf("ReadTCPResponse() message = %v, want %v", gotMsg, tt.message)
			}
			
			if !bytes.Equal(gotPad, tt.padding) {
				t.Errorf("ReadTCPResponse() padding = %v, want %v", gotPad, tt.padding)
			}
		})
	}
}

func TestWriteAndReadUDPMessage(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     uint32
		packetID      uint16
		fragmentID    uint8
		fragmentCount uint8
		address       string
		payload       []byte
		wantErr       bool
	}{
		{
			name:          "Simple message",
			sessionID:     1,
			packetID:      1,
			fragmentID:    0,
			fragmentCount: 1,
			address:       "8.8.8.8:53",
			payload:       []byte("DNS query"),
		},
		{
			name:          "Empty payload",
			sessionID:     2,
			packetID:      2,
			fragmentID:    0,
			fragmentCount: 1,
			address:       "1.1.1.1:53",
			payload:       []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			
			// Write message
			err := WriteUDPMessage(buf, tt.sessionID, tt.packetID, tt.fragmentID,
				tt.fragmentCount, tt.address, tt.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteUDPMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr {
				return
			}
			
			// Read message
			gotSID, gotPID, gotFID, gotFCount, gotAddr, gotPayload, err := ReadUDPMessage(buf)
			if err != nil {
				t.Errorf("ReadUDPMessage() error = %v", err)
				return
			}
			
			if gotSID != tt.sessionID {
				t.Errorf("ReadUDPMessage() sessionID = %v, want %v", gotSID, tt.sessionID)
			}
			
			if gotPID != tt.packetID {
				t.Errorf("ReadUDPMessage() packetID = %v, want %v", gotPID, tt.packetID)
			}
			
			if gotFID != tt.fragmentID {
				t.Errorf("ReadUDPMessage() fragmentID = %v, want %v", gotFID, tt.fragmentID)
			}
			
			if gotFCount != tt.fragmentCount {
				t.Errorf("ReadUDPMessage() fragmentCount = %v, want %v", gotFCount, tt.fragmentCount)
			}
			
			if gotAddr != tt.address {
				t.Errorf("ReadUDPMessage() address = %v, want %v", gotAddr, tt.address)
			}
			
			if !bytes.Equal(gotPayload, tt.payload) {
				t.Errorf("ReadUDPMessage() payload = %v, want %v", gotPayload, tt.payload)
			}
		})
	}
}
