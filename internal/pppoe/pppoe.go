// Package pppoe creates a PPPoE session with a remote server.
package pppoe

import (
	"context"
	"net"
	"time"
)

// Addr is a PPPoE peer address.
type Addr struct {
	// Interface is the name of the network interface over which the
	// PPPoE session is running.
	Interface string
	// SessionID is the session identifier for the PPPoE session.
	SessionID uint16
	// ConcentratorAddr is the Ethernet address of the remote PPPoE concentrator.
	ConcentratorAddr net.HardwareAddr
}

func (a *Addr) Network() string { return "pppoe" }
func (a *Addr) String() string  { return a.ConcentratorAddr.String() }

// Conn is a PPPoE connection.
type Conn struct {
	// session is both the PPPoE framer/deframer kernel object, and a
	// socket that lets you read/write packets into that
	// framer. Mostly we only want this so we can bind it to a PPP
	// interface later.
	sessionFd int
	// discovery is a raw ethernet PacketConn that we use to speak the
	// PPPoE discovery protocol. We use this to set up a session, and
	// to tear it down when we close the Conn.
	discovery net.PacketConn
	// addr is the address of the remote PPPoE concentrator. We use it
	// during session teardown, but mostly it's there to provide if
	// someone asks for Conn.RemoteAddr().
	addr Addr
	// closed is a tombstone for closed Conns, so that double-closes
	// are safe.
	closed bool
	// readDeadline is the requested deadline for reads from the
	// session socket.
	readDeadline time.Time
	// writeDeadline is the requested deadline for writes to the
	// session socket.
	writeDeadline time.Time
}

// New creates a PPPoE Conn on the given interface.
func New(ctx context.Context, ifName string) (*Conn, error) {
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

	return &Conn{
		sessionFd: sessionFd,
		discovery: disco,
		addr: Addr{
			Interface:        ifName,
			SessionID:        sessionID,
			ConcentratorAddr: concentratorAddr,
		},
	}, nil
}

// LocalAddr returns the local address of the PPPoE connection. PPPoE
// Conns don't have an interesting local address to share, so this
// returns nil for now.
func (c *Conn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the address of the connected PPPoE concentrator,
// as an *Addr.
func (c *Conn) RemoteAddr() net.Addr {
	return &c.addr
}

// Close closes the PPPoE session.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true
	sessErr := closeSessionFd(c.sessionFd)
	padtErr := sendPADT(c.discovery, c.addr.ConcentratorAddr, c.addr.SessionID)
	discErr := c.discovery.Close()
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
	return readSessionPacket(c.sessionFd, b, c.readDeadline)
}

// Write writes a packet to the PPPoE session.
func (c *Conn) Write(b []byte) (int, error) {
	return sendSessionPacket(c.sessionFd, b, c.writeDeadline)
}

// SetDeadline sets both the read and write deadlines for future Read
// and Write operations. Note that it does not alter the deadline of
// currently in-flight read/write operations, unlike fully conforming
// net.Conn implementations.
func (c *Conn) SetDeadline(deadline time.Time) error {
	// TODO: if we ever care in the future, make this function and the
	// following ones conforming, somehow?
	c.readDeadline = deadline
	c.writeDeadline = deadline
	return nil
}

// SetReadDeadline sets the deadline for future Read operations. Note
// that it does not alter the deadline of currently in-flight read
// operations, unlike fully conforming net.Conn implementations.
func (c *Conn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return nil
}

// SetWriteDeadline sets the deadline for future Write operations. Note
// that it does not alter the deadline of currently in-flight write
// operations, unlike fully conforming net.Conn implementations.
func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return nil
}

type pppoeError struct {
	msg     string
	timeout bool
}

func (e pppoeError) Error() string   { return e.msg }
func (e pppoeError) Temporary() bool { return true }
func (e pppoeError) Timeout() bool   { return e.timeout }
