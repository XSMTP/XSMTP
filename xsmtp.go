// Package xsmtp implements the XSMTP proxy protocol, designed to resist
// censorship by masquerading as SMTPS traffic.
package xsmtp

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// Message types
	TCPRequestType  = 0x01
	UDPMessageType  = 0x02
	
	// TCP Response status
	TCPStatusOK    = 0x00
	TCPStatusError = 0x01
)

// WriteVarint writes a varint to the given writer using QUIC encoding (RFC 9000)
func WriteVarint(w io.Writer, v uint64) error {
	if v < (1 << 6) {
		// 6-bit encoding
		_, err := w.Write([]byte{byte(v)})
		return err
	} else if v < (1 << 14) {
		// 14-bit encoding
		buf := []byte{byte(0x40 | (v >> 8)), byte(v)}
		_, err := w.Write(buf)
		return err
	} else if v < (1 << 30) {
		// 30-bit encoding
		buf := []byte{byte(0x80 | (v >> 24)), byte(v >> 16), byte(v >> 8), byte(v)}
		_, err := w.Write(buf)
		return err
	} else if v < (1 << 62) {
		// 62-bit encoding
		buf := []byte{byte(0xc0 | (v >> 56)), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		_, err := w.Write(buf)
		return err
	}
	return errors.New("value too large for varint")
}

// ReadVarint reads a varint from the given reader using QUIC encoding (RFC 9000)
func ReadVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	_, err := io.ReadFull(r, first[:])
	if err != nil {
		return 0, err
	}

	firstByte := first[0]
	switch firstByte >> 6 {
	case 0: // 6-bit encoding
		return uint64(firstByte), nil
	case 1: // 14-bit encoding
		var rest [1]byte
		_, err := io.ReadFull(r, rest[:])
		if err != nil {
			return 0, err
		}
		return uint64((uint16(firstByte&0x3f) << 8) | uint16(rest[0])), nil
	case 2: // 30-bit encoding
		var rest [3]byte
		_, err := io.ReadFull(r, rest[:])
		if err != nil {
			return 0, err
		}
		return uint64((uint32(firstByte&0x3f) << 24) | (uint32(rest[0]) << 16) |
			(uint32(rest[1]) << 8) | uint32(rest[2])), nil
	case 3: // 62-bit encoding
		var rest [7]byte
		_, err := io.ReadFull(r, rest[:])
		if err != nil {
			return 0, err
		}
		return (uint64(firstByte&0x3f) << 56) | (uint64(rest[0]) << 48) |
			(uint64(rest[1]) << 40) | (uint64(rest[2]) << 32) |
			(uint64(rest[3]) << 24) | (uint64(rest[4]) << 16) |
			(uint64(rest[5]) << 8) | uint64(rest[6]), nil
	default:
		// This should never happen due to the bit masking above
		return 0, errors.New("invalid varint")
	}
}

// WriteTCPRequest writes a TCP proxy request
func WriteTCPRequest(w io.Writer, address string, padding []byte) error {
	// Write request type
	if err := WriteVarint(w, TCPRequestType); err != nil {
		return err
	}
	
	// Write address length
	if err := WriteVarint(w, uint64(len(address))); err != nil {
		return err
	}
	
	// Write address
	if _, err := w.Write([]byte(address)); err != nil {
		return err
	}
	
	// Write padding length
	if err := WriteVarint(w, uint64(len(padding))); err != nil {
		return err
	}
	
	// Write padding if any
	if len(padding) > 0 {
		if _, err := w.Write(padding); err != nil {
			return err
		}
	}
	
	return nil
}

// ReadTCPRequest reads a TCP proxy request
func ReadTCPRequest(r io.Reader) (address string, padding []byte, err error) {
	// Read and verify request type
	reqType, err := ReadVarint(r)
	if err != nil {
		return "", nil, err
	}
	if reqType != TCPRequestType {
		return "", nil, errors.New("invalid request type")
	}
	
	// Read address length
	addrLen, err := ReadVarint(r)
	if err != nil {
		return "", nil, err
	}
	
	// Read address
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBytes); err != nil {
		return "", nil, err
	}
	address = string(addrBytes)
	
	// Read padding length
	paddingLen, err := ReadVarint(r)
	if err != nil {
		return "", nil, err
	}
	
	// Read padding if any
	if paddingLen > 0 {
		padding = make([]byte, paddingLen)
		if _, err := io.ReadFull(r, padding); err != nil {
			return "", nil, err
		}
	}
	
	return address, padding, nil
}

// WriteTCPResponse writes a TCP proxy response
func WriteTCPResponse(w io.Writer, status byte, message string, padding []byte) error {
	// Write status
	if _, err := w.Write([]byte{status}); err != nil {
		return err
	}
	
	// Write message length
	if err := WriteVarint(w, uint64(len(message))); err != nil {
		return err
	}
	
	// Write message if any
	if len(message) > 0 {
		if _, err := w.Write([]byte(message)); err != nil {
			return err
		}
	}
	
	// Write padding length
	if err := WriteVarint(w, uint64(len(padding))); err != nil {
		return err
	}
	
	// Write padding if any
	if len(padding) > 0 {
		if _, err := w.Write(padding); err != nil {
			return err
		}
	}
	
	return nil
}

// ReadTCPResponse reads a TCP proxy response
func ReadTCPResponse(r io.Reader) (status byte, message string, padding []byte, err error) {
	// Read status
	var statusByte [1]byte
	if _, err := io.ReadFull(r, statusByte[:]); err != nil {
		return 0, "", nil, err
	}
	status = statusByte[0]
	
	// Read message length
	msgLen, err := ReadVarint(r)
	if err != nil {
		return 0, "", nil, err
	}
	
	// Read message if any
	if msgLen > 0 {
		msgBytes := make([]byte, msgLen)
		if _, err := io.ReadFull(r, msgBytes); err != nil {
			return 0, "", nil, err
		}
		message = string(msgBytes)
	}
	
	// Read padding length
	paddingLen, err := ReadVarint(r)
	if err != nil {
		return 0, "", nil, err
	}
	
	// Read padding if any
	if paddingLen > 0 {
		padding = make([]byte, paddingLen)
		if _, err := io.ReadFull(r, padding); err != nil {
			return 0, "", nil, err
		}
	}
	
	return status, message, padding, nil
}

// WriteUDPMessage writes a UDP message
func WriteUDPMessage(w io.Writer, sessionID uint32, packetID uint16, fragmentID, fragmentCount uint8, 
					address string, payload []byte) error {
	// Write message type
	if err := WriteVarint(w, UDPMessageType); err != nil {
		return err
	}
	
	// Write session ID
	if err := binary.Write(w, binary.BigEndian, sessionID); err != nil {
		return err
	}
	
	// Write packet ID
	if err := binary.Write(w, binary.BigEndian, packetID); err != nil {
		return err
	}
	
	// Write fragment ID and count
	if _, err := w.Write([]byte{fragmentID, fragmentCount}); err != nil {
		return err
	}
	
	// Write address length
	if err := WriteVarint(w, uint64(len(address))); err != nil {
		return err
	}
	
	// Write address
	if _, err := w.Write([]byte(address)); err != nil {
		return err
	}
	
	// Write payload length
	if err := WriteVarint(w, uint64(len(payload))); err != nil {
		return err
	}
	
	// Write payload
	if _, err := w.Write(payload); err != nil {
		return err
	}
	
	return nil
}

// ReadUDPMessage reads a UDP message
func ReadUDPMessage(r io.Reader) (sessionID uint32, packetID uint16, fragmentID, fragmentCount uint8,
							address string, payload []byte, err error) {
	// Read and verify message type
	msgType, err := ReadVarint(r)
	if err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	if msgType != UDPMessageType {
		return 0, 0, 0, 0, "", nil, errors.New("invalid message type")
	}
	
	// Read session ID
	if err := binary.Read(r, binary.BigEndian, &sessionID); err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	
	// Read packet ID
	if err := binary.Read(r, binary.BigEndian, &packetID); err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	
	// Read fragment ID and count
	var fragBytes [2]byte
	if _, err := io.ReadFull(r, fragBytes[:]); err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	fragmentID = fragBytes[0]
	fragmentCount = fragBytes[1]
	
	// Read address length
	addrLen, err := ReadVarint(r)
	if err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	
	// Read address
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBytes); err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	address = string(addrBytes)
	
	// Read payload length
	payloadLen, err := ReadVarint(r)
	if err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	
	// Read payload
	payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, 0, 0, "", nil, err
	}
	
	return sessionID, packetID, fragmentID, fragmentCount, address, payload, nil
}
