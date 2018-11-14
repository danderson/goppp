package ppp

import (
	"fmt"
	"net"

	"github.com/mdlayher/raw"
)

const (
	protoPPPoEDiscovery = 0x8863
	protoPPPoESession   = 0x8864
)

var (
	padiPacket = []byte{
		0x11, // Protocol version 1, packet type 1 (both constants)
		9,    // Code PADI, aka "hey any PPPoE concentrators out there?"
		0, 0, // Session ID not set during discovery
		0, 4, // Payload length - payload is a TLV array of tags, but we're sending only 1 zero-length tag
		1, 1, // Tag "Service-Name", aka "which ISP is acceptable to me?
		0, 0, // Tag value length = 0
		// No tag value, meaning "any ISP is acceptable"
	}
	ethernetBroadcast = &raw.Addr{
		HardwareAddr: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
)

func pppoeDiscovery(ifName string) (sessionID uint16, err error) {
	intf, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, fmt.Errorf("getting interface: %s", err)
	}
	conn, err := raw.ListenPacket(intf, protoPPPoEDiscovery, &raw.Config{LinuxSockDGRAM: true})
	if err != nil {
		return 0, fmt.Errorf("creating PPPoE Discovery listener: %s", err)
	}
	defer conn.Close()

	if _, err := conn.WriteTo(padiPacket, ethernetBroadcast); err != nil {
		return 0, fmt.Errorf("sending PADI packet: %s", err)
	}

	return 0, nil
}
