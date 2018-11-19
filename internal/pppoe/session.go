package pppoe

import (
	"net"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const protoPPPoE = 0 // Stolen from /usr/include/linux/if_pppox.h

func newSessionFd(ifName string) (int, error) {
	return unix.Socket(unix.AF_PPPOX, unix.SOCK_STREAM, protoPPPoE)
}

func closeSessionFd(fd int) error {
	return unix.Close(fd)
}

func connectSessionFd(fd int, ifName string, remote net.HardwareAddr, sessionID uint16) error {
	sa := &unix.SockaddrPPPoE{
		SID:    sessionID,
		Remote: remote,
		Dev:    ifName,
	}
	return unix.Connect(fd, sa)
}

func newChannel(sessionFd int) (*os.File, error) {
	f, err := os.OpenFile("/dev/ppp", os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	channelID, err := unix.IoctlGetInt(sessionFd, unix.PPPIOCGCHAN)
	if err != nil {
		f.Close()
		return nil, err
	}

	// At this point sessionFd is kinda horked, because reading the
	// channel ID switches the channel to the BOUND state, where it
	// will only talk to the ppp generic driver. So, we need to bind
	// that channel to the /dev/ppp File we just opened.

	if err := unix.IoctlSetInt(int(f.Fd()), unix.PPPIOCATTCHAN, int(uintptr(unsafe.Pointer(&channelID)))); err != nil {
		f.Close()
		return nil, err
	}
	// We're passing a pointer to the channelID int into the
	// kernel. It needs to stay alive until the syscall
	// completes. This is what runtime.Keepalive does.
	//
	// In theory it's overkill because channelID is on the stack
	// frame, but who knows, the compiler might decide to put it on
	// the heap for some reason. Worst case, it does nothing, but it's
	// not actively harmful, so it's fine.
	runtime.KeepAlive(&channelID)

	return f, nil
}
