// Package pppoe creates a PPPoE session with a remote server.
package pppoe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/mdlayher/raw"
)

// Constants for PPPoE protocol EtherTypes.
const (
	protoPPPoEDiscovery = 0x8863
	protoPPPoESession   = 0x8864
)

// Constants for PPPoE Discovery packet types.
const (
	pppoePADI = 0x09 // "Hey, any PPPoE concentrators out there?
	pppoePADO = 0x07 // "Hi, I'm a PPPoE concentrator"
	pppoePADR = 0x19 // "Cool, can we set up a PPPoE session?"
	pppoePADS = 0x65 // "Done, here's the session ID!"
	pppoePADT = 0xa7 // "I'm tearing down our session"
)

// Constants for PPPoE Discovery tag types
const (
	pppoeTagServiceName = 0x0101 // Roughly speaking, the name of the ISP.
	pppoeTagACName      = 0x0102 // Roughly speaking, the hostname of the PPPoE concentrator.
	pppoeTagCookie      = 0x0104 // The PPPoE equivalent of a syncookie.
)

var (
	// padiPacket is a PPPoE Active Discovery Initiation (PADI) packet
	// that sollicits session offers from any available PPPoE
	// concentrator.
	padiPacket = encodeDiscoveryPacket(&discoveryPacket{
		Code: pppoePADI,
		Tags: map[int][]byte{
			// By convention on single-ISP customer access networks,
			// the tag is always nil, meaning "don't care," because
			// there's only one ISP around anyway.
			pppoeTagServiceName: nil,
		},
	})
	// ethernetBroadcast is the Ethernet broadcast address.
	ethernetBroadcast = &raw.Addr{
		HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
)

// pppoeDiscovery executes PPPoE discovery and returns a PPPoE session ID.
func pppoeDiscovery(ctx context.Context, ifName string) (sessionID int, closer func() error, err error) {
	conn, err := newDiscoveryConn(ifName)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	deadline, hasDeadline := ctx.Deadline()

	var (
		concentrator net.Addr
		cookie       []byte
	)

	// Broadcast PADIs, looking for a PPPoE concentrator.
	for concentrator == nil && (!hasDeadline || time.Now().Before(deadline)) {
		// Send a PADI, asking concentrators for a session offer.
		if err := sendPADI(conn); err != nil {
			return 0, nil, fmt.Errorf("sending PADI packet: %v", err)
		}

		padoCtx, cancelPADO := context.WithTimeout(ctx, time.Second)
		defer cancelPADO()
		concentrator, cookie, err = readPADO(padoCtx, conn)
		if err == nil {
			// We know about a concentrator, move on.
			break
		} else if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
			return 0, nil, fmt.Errorf("waiting for PADO: %v", err)
		}
		// Timed out waiting for PADO. Loop back around to (maybe) try
		// again.
	}

	// Got a concentrator, request a session.
	for !hasDeadline || time.Now().Before(deadline) {
		if err := sendPADR(conn, concentrator, cookie); err != nil {
			return 0, nil, fmt.Errorf("sending PADR packet: %v", err)
		}

		padsCtx, cancelPADS := context.WithTimeout(ctx, time.Second)
		defer cancelPADS()
		sessionID, err = readPADS(padsCtx, conn, concentrator)
		if err == nil {
			// We're done!
			return sessionID, func() error { return sendPADT(conn, concentrator, sessionID) }, nil
		} else if neterr, ok := err.(net.Error); !ok || !neterr.Timeout() {
			return 0, nil, fmt.Errorf("waiting for PADS: %v", err)
		}
		// Timed out waiting for PADS. Loop back around to (maybe) try
		// again.
	}

	// Oops, deadline exceeded :(
	return 0, nil, ctx.Err()
}

// newDiscoveryConn creates a net.PacketConn that can receive PPPoE
// discovery packets.
func newDiscoveryConn(ifName string) (net.PacketConn, error) {
	intf, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %v: %v", ifName, err)
	}
	conn, err := raw.ListenPacket(intf, protoPPPoEDiscovery, &raw.Config{LinuxSockDGRAM: true})
	if err != nil {
		return nil, fmt.Errorf("creating PPPoE Discovery listener: %v", err)
	}
	return conn, nil
}

// sendPADI broadcasts a PADI packet. While trivial, it's separated
// out so tests can invoke it.
func sendPADI(conn net.PacketConn) error {
	_, err := conn.WriteTo(padiPacket, ethernetBroadcast)
	return err
}

// readPADO waits to receive a valid PPPoE Active Discovery Offer
// (PADO) packet, and returns relevant information from it.
func readPADO(ctx context.Context, conn net.PacketConn) (concentratorAddr net.Addr, cookie []byte, err error) {
	var b [1500]byte

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(deadline)
		defer conn.SetReadDeadline(time.Time{})
	}
	for {
		n, from, err := conn.ReadFrom(b[:])
		if err != nil {
			return nil, nil, err
		}

		cookie, err := parsePADO(b[:n])
		if err == nil {
			return from, cookie, nil
		}

		// Not a valid PADO, keep waiting
	}
}

// parsePADO parses a raw PADO packet and extracts the PPPoE cookie.
func parsePADO(buf []byte) (cookie []byte, err error) {
	pkt, err := parseDiscoveryPacket(buf)
	if err != nil {
		return nil, err
	}
	if pkt.Code != pppoePADO {
		return nil, errors.New("not a PADO packet")
	}
	if pkt.SessionID != 0 {
		return nil, errors.New("non-zero session ID")
	}

	// Note, not having a cookie is fine. Its function is similar to
	// syncookies, an anti-DoS measure at the concentrator. If the
	// concentrator doesn't care, then neither do we.
	return pkt.Tags[pppoeTagCookie], nil
}

func sendPADR(conn net.PacketConn, concentrator net.Addr, cookie []byte) error {
	pkt := &discoveryPacket{
		Code: pppoePADR,
		Tags: map[int][]byte{
			pppoeTagServiceName: nil,
		},
	}
	if len(cookie) != 0 {
		pkt.Tags[pppoeTagCookie] = cookie
	}
	_, err := conn.WriteTo(encodeDiscoveryPacket(pkt), concentrator)
	return err
}

func readPADS(ctx context.Context, conn net.PacketConn, concentrator net.Addr) (sessionID int, err error) {
	var b [1500]byte

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetReadDeadline(deadline)
		defer conn.SetReadDeadline(time.Time{})
	}
	for {
		n, from, err := conn.ReadFrom(b[:])
		if err != nil {
			return 0, err
		}

		if concentrator.String() != from.String() {
			// Wrong peer, keep waiting
			continue
		}

		sessionID, err = parsePADS(b[:n])
		if err == nil {
			return sessionID, nil
		}

		// Not a valid PADO, keep waiting
	}
}

func parsePADS(buf []byte) (sessionID int, err error) {
	pkt, err := parseDiscoveryPacket(buf)
	if err != nil {
		return 0, err
	}
	if pkt.Code != pppoePADS {
		return 0, errors.New("not a PADS packet")
	}
	return pkt.SessionID, nil
}

func sendPADT(conn net.PacketConn, concentrator net.Addr, sessionID int) error {
	pkt := &discoveryPacket{
		Code:      pppoePADT,
		SessionID: sessionID,
	}
	_, err := conn.WriteTo(encodeDiscoveryPacket(pkt), concentrator)
	conn.Close()
	return err
}

// discoveryPacket is a parsed PPPoE Discovery packet.
type discoveryPacket struct {
	// Code is the kind of PPPoE packet.
	Code int
	// SessionID is the PPPoE session ID. It's zero for all Discovery
	// packets except PADS and PADT.
	SessionID int
	// Tags is a collection of key/value pairs attached to the
	// packet. Required/optional tags vary depending on Code.
	Tags map[int][]byte
}

// parseDiscoveryPacket parses a PPPoE Discovery packet into a discoveryPacket.
func parseDiscoveryPacket(pkt []byte) (*discoveryPacket, error) {
	if len(pkt) < 6 {
		return nil, errors.New("packet too short to be PPPoE Discovery")
	}
	if pkt[0] != 0x11 {
		return nil, fmt.Errorf("unknown PPPoE version %x", pkt[0])
	}

	ret := &discoveryPacket{
		Code:      int(pkt[1]),
		SessionID: int(binary.BigEndian.Uint16(pkt[2:4])),
		Tags:      map[int][]byte{},
	}

	tlvLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	pkt = pkt[6:]
	if tlvLen != len(pkt) {
		return nil, fmt.Errorf("Tag array length %v doesn't match remaining packet length %v", tlvLen, len(pkt))
	}

	for len(pkt) > 0 {
		if len(pkt) < 4 {
			return nil, fmt.Errorf("%d bytes of trailing garbage at end of packet", len(pkt))
		}

		tagType, tagLen := int(binary.BigEndian.Uint16(pkt[:2])), int(binary.BigEndian.Uint16(pkt[2:4]))
		if len(pkt[4:]) < tagLen {
			return nil, errors.New("tag declared length larger than remaining packet")
		}

		tagValue := pkt[4 : 4+tagLen]
		pkt = pkt[4+tagLen:]

		if tagType == pppoeTagServiceName && tagLen != 0 {
			return nil, errors.New("unexpected non-nil Service-Name tag")
		}

		ret.Tags[tagType] = tagValue
	}

	return ret, nil
}

// encodeDiscoveryPacket marshals a PPPoE Discovery packet into raw bytes.
func encodeDiscoveryPacket(pkt *discoveryPacket) []byte {
	tlvLen, tlvs := 0, []int{}
	for tlv, val := range pkt.Tags {
		tlvs = append(tlvs, tlv)
		tlvLen += len(val)
	}
	sort.Ints(tlvs)

	var ret bytes.Buffer
	ret.WriteByte(0x11)            // Protocol version 1, packet type 1
	ret.WriteByte(uint8(pkt.Code)) // PPPoE packet code
	binary.Write(&ret, binary.BigEndian, uint16(pkt.SessionID))
	binary.Write(&ret, binary.BigEndian, uint16(tlvLen+(4*len(pkt.Tags))))

	for _, tlv := range tlvs {
		val := pkt.Tags[tlv]
		binary.Write(&ret, binary.BigEndian, uint16(tlv))
		binary.Write(&ret, binary.BigEndian, uint16(len(val)))
		ret.Write(val)
	}

	return ret.Bytes()
}
