package pppoe

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const protoPPPoE = 0 // Stolen from /usr/include/linux/if_pppox.h

func newSessionFd(ifName string) (int, error) {
	return unix.Socket(unix.AF_PPPOX, unix.SOCK_STREAM, protoPPPoE)
}

func closeSessionFd(fd int) error {
	return unix.Close(fd)
}

func connectSessionFd(fd int, ifName string, remote net.HardwareAddr, sessionID int) error {
	sa := &unix.SockaddrPPPoE{
		SID:    uint16(sessionID),
		Remote: remote,
		Dev:    ifName,
	}
	return unix.Connect(fd, sa)
}

func sendSessionPacket(fd int, pkt []byte) error {
	n, err := unix.Write(fd, pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("short socket write: got %d, want %d", n, len(pkt))
	}
	return nil
}

func readSessionPacket(fd int, buf []byte) (n int, from unix.Sockaddr, err error) {
	return unix.Recvfrom(fd, buf, 0)
}
