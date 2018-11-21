// Package lcp implements parsing and serialization of the PPP Link Control Protocol.
package lcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Code is the type of an LCP packet.
type Code uint8

// Proto is the PPP protocol number for the Link Control Protocol.
const Proto = 0xc021

// Constants for LCP packet types.
const (
	typeConfigureRequest Code = 1
	typeConfigureAck     Code = 2
	typeConfigureNak     Code = 3
	typeConfigureReject  Code = 4
	typeTerminateRequest Code = 5
	typeTerminateAck     Code = 6
	typeCodeReject       Code = 7
	typeProtocolReject   Code = 8
	typeEchoRequest      Code = 9
	typeEchoReply        Code = 10
	typeDiscardRequest   Code = 11
)

const (
	optionMRU       = 1
	optionAuthProto = 3
	optionMagic     = 5
)

var errUnexpectedLen = errors.New("unexpected length for packet field")

type Packet struct {
	Code Code
	ID   uint8

	// Used only when code = typeConfigureRequest, typeConfigureAck,
	// typeConfigureNak, typeConfigureReject.
	MRU            uint16
	AuthProto      uint16
	CHAPAlgorithm  uint8
	UnknownOptions map[uint8][]byte

	// Used only when code = typeTerminateRequest, typeTerminateAck,
	// typeCodeReject, typeProtocolReject, typeEchoRequest,
	// typeEchoReply, typeDiscardRequest.
	Data []byte

	// Used only when code = typeProtocolReject
	RejectedProtocol uint16

	// Used only when code = typeConfigureRequest, typeConfigureAck,
	// typeConfigureNak, typeConfigureReject, typeEchoRequest,
	// typeEchoReply, typeDiscardRequest
	Magic uint32
}

// Parse parses and returns an LCP PPP frame. b may have trailing
// padding, which Parse will ignore. Depending on the packet type, the
// returned Packet may reference b in some slices.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(b[:2]) != Proto {
		return nil, errors.New("not an LCP packet")
	}
	b = b[2:] // Advance past PPP frame, to start of LCP packet.

	ret := &Packet{
		Code: Code(b[0]),
		ID:   b[1],
	}
	pktLen := int(binary.BigEndian.Uint16(b[2:4]))
	// Note that pktLen == len(b) is not required. PPP explicitly
	// allows trailing padding to be inserted by the framing layer,
	// and requires that inner protocols like LCP should gracefully
	// ignore any padding.
	//
	// So, we only check if the declared packet length is
	// nonsensically short, or overflows the total packet size.
	if pktLen < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	if pktLen > len(b) {
		return nil, io.ErrUnexpectedEOF
	}

	b = b[4:pktLen] // Advance to packet payload

	switch ret.Code {
	case typeConfigureRequest, typeConfigureAck, typeConfigureNak, typeConfigureReject:
		opts, err := parseLCPOptions(b)
		if err != nil {
			return nil, err
		}
		for opt, val := range opts {
			switch opt {
			case optionMRU:
				if len(val) != 2 {
					return nil, errUnexpectedLen
				}
				ret.MRU = binary.BigEndian.Uint16(val)
				delete(opts, opt)
			case optionAuthProto:
				if len(val) < 2 {
					return nil, io.ErrUnexpectedEOF
				}
				ret.AuthProto = binary.BigEndian.Uint16(val[:2])
				if ret.AuthProto == 0xc223 {
					if len(val) != 3 {
						return nil, errUnexpectedLen
					}
					ret.CHAPAlgorithm = val[2]
				} else if len(val) != 2 {
					return nil, errUnexpectedLen
				}
				delete(opts, opt)
			case optionMagic:
				if len(val) != 4 {
					return nil, errUnexpectedLen
				}
				ret.Magic = binary.BigEndian.Uint32(val)
				delete(opts, opt)
			}
		}
		ret.UnknownOptions = opts

	case typeProtocolReject:
		if len(b) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		ret.RejectedProtocol = binary.BigEndian.Uint16(b[:2])
		b = b[2:]
		fallthrough
	case typeTerminateRequest, typeTerminateAck, typeCodeReject:
		ret.Data = b

	case typeEchoRequest, typeEchoReply, typeDiscardRequest:
		if len(b) < 4 {
			return nil, errors.New("packet too short")
		}
		ret.Magic = binary.BigEndian.Uint32(b[:4])
		ret.Data = b[4:]

	default:
		return nil, fmt.Errorf("unknown LCP packet type %x", ret.Code)
	}

	return ret, nil
}

func parseLCPOptions(b []byte) (map[uint8][]byte, error) {
	ret := map[uint8][]byte{}

	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("trailing garbage at end of packet")
		}
		optionType, optionLen := b[0], int(b[1])
		if optionLen < 2 {
			return nil, fmt.Errorf("option length %d for option %d is too short", optionLen, optionType)
		}
		if optionLen > len(b) {
			return nil, fmt.Errorf("option length %d for option %d overflows packet", optionLen, optionType)
		}
		ret[optionType] = b[2:optionLen]
		b = b[optionLen:]
	}

	return ret, nil
}

// Bytes serializes an LCP packet into a PPP frame for transmission.
func (p *Packet) Bytes() []byte {
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint16(Proto))
	out.WriteByte(uint8(p.Code))
	out.WriteByte(p.ID)
	// Total packet length, overwritten later
	out.WriteByte(0)
	out.WriteByte(0)

	switch p.Code {
	case typeConfigureRequest, typeConfigureAck, typeConfigureNak, typeConfigureReject:
		if p.MRU != 0 {
			out.WriteByte(optionMRU)
			out.WriteByte(4)
			binary.Write(&out, binary.BigEndian, p.MRU)
		}
		if p.AuthProto != 0 {
			out.WriteByte(optionAuthProto)
			if p.CHAPAlgorithm != 0 {
				out.WriteByte(5)
			} else {
				out.WriteByte(4)
			}
			binary.Write(&out, binary.BigEndian, p.AuthProto)
			if p.CHAPAlgorithm != 0 {
				out.WriteByte(p.CHAPAlgorithm)
			}
		}
		if p.Magic != 0 {
			out.WriteByte(optionMagic)
			out.WriteByte(6)
			binary.Write(&out, binary.BigEndian, p.Magic)
		}
		for opt, val := range p.UnknownOptions {
			out.WriteByte(opt)
			out.WriteByte(uint8(len(val) + 2))
			out.Write(val)
		}

	case typeProtocolReject:
		binary.Write(&out, binary.BigEndian, p.RejectedProtocol)
		fallthrough
	case typeTerminateRequest, typeTerminateAck, typeCodeReject:
		out.Write(p.Data)
	case typeEchoRequest, typeEchoReply, typeDiscardRequest:
		binary.Write(&out, binary.BigEndian, p.Magic)
		out.Write(p.Data)
	}

	ret := out.Bytes()
	// Overwrite the total LCP frame length with total number of bytes
	// except the first two, which are the PPP frame type.
	binary.BigEndian.PutUint16(ret[4:6], uint16(len(ret)-2))
	return ret
}
