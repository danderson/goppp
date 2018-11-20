// Package pppoe creates a PPPoE session with a remote server.
package pppoe // import "go.universe.tf/ppp/pppoe"

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

// Addr is a PPPoE peer address.
type Addr struct {
	// Interface is the name of the network interface over which the
	// PPPoE session is running.
	Interface string
	// SessionID is the session identifier for the PPPoE session.
	SessionID uint16
	// HardwareAddr is the Ethernet address of the PPPoE endpoint.
	HardwareAddr net.HardwareAddr
}

func (a *Addr) Network() string { return "pppoe" }
func (a *Addr) String() string  { return a.HardwareAddr.String() }

// Conn is a PPPoE connection.
type Conn struct {
	// session is the PPPoE framer/deframer kernel object. We need to
	// keep this open to keep the kernel object alive, but we don't
	// talk to it through this fd. For talking, see the next fd.
	sessionFd int
	// channel is the PPP channel that sends over PPPoE. This is a
	// handle to the generic PPP channel object in the kernel that
	// wraps the above PPPoE session object. We can use this to
	// send/receive control packets.
	channel *os.File
	// discovery is a raw ethernet PacketConn that we use to speak the
	// PPPoE discovery protocol. We use this to set up a session, and
	// to tear it down when we close the Conn.
	discovery net.PacketConn
	// localAddr is the address of the local PPPoE endpoint. It exists
	// to provide in response to LocalAddr.
	localAddr *Addr
	// remoteAddr is the address of the remote PPPoE concentrator. We
	// use it during session teardown, but mostly it exists to provide
	// if someone asks for RemoteAddr.
	remoteAddr *Addr
	// closed is a tombstone for closed Conns, so that double-closes
	// are safe.
	closed bool
}

// New runs PPPoE discovery on the given interface, and creates a Conn
// that can send PPP frames on the resulting PPPoE session.
func New(ctx context.Context, ifName string) (*Conn, error) {
	intf, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	if len(intf.HardwareAddr) != 6 {
		return nil, fmt.Errorf("%q has a non-ethernet hardware type", ifName)
	}

	disco, err := newDiscoveryConn(ifName)
	if err != nil {
		return nil, err
	}

	// Create the session file descriptor before executing PPPoE
	// discovery, because the concentrator will immediately start
	// sending PPP packets, and having the session fd open means we
	// catch those packets.
	sessionFd, err := newSessionFd(ifName)
	if err != nil {
		disco.Close()
		return nil, err
	}

	concentratorAddr, sessionID, err := pppoeDiscovery(ctx, disco)
	if err != nil {
		closeSessionFd(sessionFd)
		disco.Close()
		return nil, err
	}

	// Connect the session fd. This doesn't do much, other than allow
	// a few more ioctl()s to be applied later on.
	if err = connectSessionFd(sessionFd, ifName, concentratorAddr, sessionID); err != nil {
		closeSessionFd(sessionFd)
		disco.Close()
		return nil, err
	}

	// Create the channel.
	f, err := newChannel(sessionFd)
	if err != nil {
		closeSessionFd(sessionFd)
		disco.Close()
		return nil, err
	}

	return &Conn{
		sessionFd: sessionFd,
		channel:   f,
		discovery: disco,
		localAddr: &Addr{
			Interface:    ifName,
			SessionID:    sessionID,
			HardwareAddr: intf.HardwareAddr,
		},
		remoteAddr: &Addr{
			Interface:    ifName,
			SessionID:    sessionID,
			HardwareAddr: concentratorAddr,
		},
	}, nil
}

// LocalAddr returns the local address of the PPPoE connection. PPPoE
// Conns don't have an interesting local address to share, so this
// returns nil for now.
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the address of the connected PPPoE concentrator,
// as an *Addr.
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Close closes the PPPoE session.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true
	channelErr := c.channel.Close()
	sessErr := closeSessionFd(c.sessionFd)
	padtErr := sendPADT(c.discovery, c.remoteAddr.HardwareAddr, c.remoteAddr.SessionID)
	discErr := c.discovery.Close()
	if channelErr != nil {
		return channelErr
	}
	if sessErr != nil {
		return sessErr
	}
	if padtErr != nil {
		return padtErr
	}
	if discErr != nil {
		return discErr
	}
	return nil
}

// Read reads a packet from the PPPoE session.
func (c *Conn) Read(b []byte) (int, error) {
	return c.channel.Read(b)
}

// Write writes a packet to the PPPoE session.
func (c *Conn) Write(b []byte) (int, error) {
	return c.channel.Write(b)
}

// SetDeadline sets both the read and write deadlines for future Read
// and Write operations.
func (c *Conn) SetDeadline(deadline time.Time) error {
	return c.channel.SetDeadline(deadline)
}

// SetReadDeadline sets the deadline for future Read operations.
func (c *Conn) SetReadDeadline(deadline time.Time) error {
	return c.channel.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the deadline for future Write operations.
func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	return c.channel.SetWriteDeadline(deadline)
}
