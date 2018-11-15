package pppoe

import (
	"context"
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

	// TODO: test drive the session by sending some packets.
}
