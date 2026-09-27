package platform

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// WatchTopology signals, coalesced, after rtnetlink reports a link, address,
// route or policy-rule change. Neighbor churn is excluded. The channel closes
// when ctx ends or the socket fails; callers keep polling as the fallback.
func WatchTopology(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_RULE | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// IPv6 rules have no legacy group bit.
	_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_IPV6_RULE)
	f := os.NewFile(uintptr(fd), "rtnetlink")
	ch := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		f.Close()
	}()
	go func() {
		defer close(ch)
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, err := f.Read(buf)
			if errors.Is(err, unix.ENOBUFS) {
				// Messages were lost to overrun; a change certainly happened.
				n, err = 1, nil
			}
			if err != nil {
				return
			}
			if n > 0 {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch, nil
}
