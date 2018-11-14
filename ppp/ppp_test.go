// package ppp implements establishing a PPP connection running over PPPoE.
package ppp

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/raw"
)

func canUseDocker() error {
	cmd := exec.Command("docker", "ps")
	return cmd.Run()
}

func canUseRawSockets() error {
	intf, err := net.InterfaceByName("docker0")
	if err != nil {
		return fmt.Errorf("getting interface: %v", err)
	}
	conn, err := raw.ListenPacket(intf, protoPPPoEDiscovery, &raw.Config{LinuxSockDGRAM: true})
	if err != nil {
		return fmt.Errorf("creating PPPoE Discovery listener: %v", err)
	}
	defer conn.Close()
	return nil
}

func canTest() error {
	if err := canUseRawSockets(); err != nil {
		return err
	}
	if err := canUseDocker(); err != nil {
		return err
	}
	return nil
}

func startServer() (func(), error) {
	if err := canUseDocker(); err != nil {
		return nil, fmt.Errorf("can't run docker: %v", err)
	}

	cmd := exec.Command("docker", "run", "--rm", "-d", "--cap-add=NET_ADMIN", "--device=/dev/ppp", "goppp:testing")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(string(out))

	closeFunc := func() {
		cmd := exec.Command("docker", "kill", id)
		cmd.Run()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		intf, err := net.InterfaceByName("docker0")
		if err != nil {
			closeFunc()
			return nil, err
		}

		if intf.Flags&net.FlagUp != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return closeFunc, nil
}

func TestDiscovery(t *testing.T) {
	if err := canTest(); err != nil {
		t.Skipf("can't run privileged tests: %v", err)
	}

	close, err := startServer()
	if err != nil {
		t.Fatalf("couldn't start pppd container: %v", err)
	}
	defer close()

	pppoeDiscovery("docker0")
}
