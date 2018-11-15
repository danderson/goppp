// package testutil contains some helpers for testing PPP and PPPoE connections.
package testutil

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
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
	conn, err := raw.ListenPacket(intf, 0x8863, &raw.Config{LinuxSockDGRAM: true})
	if err != nil {
		return fmt.Errorf("creating PPPoE Discovery listener: %v", err)
	}
	defer conn.Close()
	return nil
}

// CanRunPrivilegedTests returns nil if Docker and raw socket based tests can be run.
func CanRunPrivilegedTests() error {
	if err := canUseRawSockets(); err != nil {
		return err
	}
	if err := canUseDocker(); err != nil {
		return err
	}
	return nil
}

// StartServer runs a PPP+PPPoE server in a Docker container. Returns
// a closer function (which should be defer-ed), or an error if server
// startup fails.
func StartServer() (func(), error) {
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
