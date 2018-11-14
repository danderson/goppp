// Package ppp establishes a PPP connection running over PPPoE.
package ppp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/raw"
)

// Constants for PPPoE protocol EtherTypes.
const (
	protoPPPoEDiscovery = 0x8863
	protoPPPoESession   = 0x8864
)

var (
	// padiPacket is a PPPoE Active Discovery Initiation (PADI) packet
	// that sollicits session offers from any available PPPoE
	// concentrator.
	padiPacket = []byte{
		0x11, // Protocol version 1, packet type 1 (both constants)
		9,    // Code PADI, aka "hey any PPPoE concentrators out there?"
		0, 0, // Session ID, not set during discovery
		0, 4, // Payload length. payload is a TLV array of tags, but we're sending only 1 zero-length tag
		1, 1, // Tag "Service-Name", aka "which ISP is acceptable to me?
		0, 0, // Tag value length, 0
		// No tag value, meaning "any ISP is acceptable"
	}
	// ethernetBroadcast is the Ethernet broadcast address.
	ethernetBroadcast = &raw.Addr{
		HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
)

// pppoeDiscovery executes PPPoE discovery and returns a PPPoE session ID.
func pppoeDiscovery(ctx context.Context, ifName string) (sessionID uint16, err error) {
	conn, err := newDiscoveryConn(ifName)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	deadline, hasDeadline := ctx.Deadline()

	for !hasDeadline || time.Now().Before(deadline) {
		// Send a PADI, asking concentrators for a session offer.
		if err := sendPADI(conn); err != nil {
			return 0, fmt.Errorf("sending PADI packet: %v", err)
		}

		padoCtx, cancelPado := context.WithTimeout(ctx, time.Second)
		defer cancelPado()
		concentrator, cookie, err := readPADO(padoCtx, conn)
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				// Timed out waiting for PADO. Resend PADI and wait again.
				continue
			}
		}
		fmt.Println(concentrator, cookie)
		break
	}

	panic("TODO")
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
func parsePADO(pkt []byte) (cookie []byte, err error) {
	if len(pkt) < 6 {
		return nil, errors.New("packet too short to be PADO")
	}
	if pkt[0] != 0x11 {
		return nil, fmt.Errorf("unknown PPPoE version %x", pkt[0])
	}
	if pkt[1] != 7 {
		return nil, errors.New("not a PADO packet")
	}
	if pkt[2] != 0 || pkt[3] != 0 {
		return nil, errors.New("non-zero session ID")
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

		switch tagType {
		case 0x0104:
			cookie = tagValue
		case 0x0101:
			if tagLen != 0 {
				return nil, errors.New("service name tag doesn't match the one requested in PADI")
			}
		}
	}

	// Note, not having a cookie is fine. Its function is similar to
	// syncookies, an anti-DoS measure at the concentrator. If the
	// concentrator doesn't care, then neither do we.
	return cookie, nil
}
