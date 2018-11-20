package pppoe

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"go.universe.tf/ppp/internal/testutil"
)

func TestNew(t *testing.T) {
	if err := testutil.CheckPrivilegeForContainerTests(); err != nil {
		t.Skipf("can't run privileged tests: %v", err)
	}

	close, err := testutil.StartServer()
	if err != nil {
		t.Fatalf("couldn't start pppd container: %v", err)
	}
	defer close()

	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()

	conn, err := New(ctx, "docker0")
	if err != nil {
		t.Fatalf("PPPoE session setup failed: %v", err)
	}
	defer conn.Close()

	lcpHello := []byte{
		0xc0, 0x21, // PPP protocol: LCP
		1,    // Configure-Request
		1,    // Request ID
		0, 0, // Length of tags
	}
	if _, err := conn.Write(lcpHello); err != nil {
		t.Fatalf("writing to PPPoE session: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting read deadline: %v", err)
	}

	// Read back and just check that the frame we read is a PPP LCP
	// packet. The server could be sending us a couple of different
	// ones, so we just check that it looks plausible.
	var b [pppoeBufferLen]byte
	n, err := conn.Read(b[:])
	if err != nil {
		t.Fatalf("reading from PPPoE session: %v", err)
	}
	if n < 2 {
		t.Fatal("impossibly short PPPoE session packet")
	}
	proto := binary.BigEndian.Uint16(b[:2])
	if proto != 0xc021 {
		t.Fatalf("wrong PPP protocol, got %4x, want c021", proto)
	}
}
