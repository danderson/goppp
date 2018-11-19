package pppoe

import (
	"errors"
	"fmt"
	"net"
	"time"

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

func sendSessionPacket(fd int, pkt []byte, deadline time.Time) (n int, err error) {
	if !deadline.IsZero() {
		if err = setTimeout(fd, unix.SO_SNDTIMEO, deadline); err != nil {
			return 0, err
		}
		defer func() {
			resetErr := setTimeout(fd, unix.SO_SNDTIMEO, time.Time{})
			if err == nil && resetErr != nil {
				err = resetErr
			}
		}()
	}
	n, err = unix.Write(fd, pkt)
	if err != nil {
		return n, err
	}
	if n != len(pkt) {
		return n, fmt.Errorf("short socket write: got %d, want %d", n, len(pkt))
	}
	return n, nil
}

func readSessionPacket(fd int, buf []byte, deadline time.Time) (n int, err error) {
	if !deadline.IsZero() {
		if err = setTimeout(fd, unix.SO_RCVTIMEO, deadline); err != nil {
			return 0, err
		}
		defer func() {
			resetErr := setTimeout(fd, unix.SO_RCVTIMEO, time.Time{})
			if err == nil && resetErr != nil {
				err = resetErr
			}
		}()
	}
	return unix.Read(fd, buf)
}

func setTimeout(fd int, opt int, deadline time.Time) error {
	var tv unix.Timeval
	if !deadline.IsZero() {
		d := time.Until(deadline).Truncate(time.Microsecond)
		if d < 0 {
			return errors.New("timeout") // TODO: net.Error
		}
		tv.Sec = int64(d.Seconds())
		tv.Usec = (d.Nanoseconds() / 1e3) - (tv.Sec * 1e6)
	}
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}
