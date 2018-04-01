
package main

import (
	"encoding/binary"
	"sync/atomic"
	"time"
)

// The length of time before entries in the filter map are considered stale.
const expireTimeout = 300

// The current timestamp in seconds. Must be read using atomic operations.
var atomicNow uint64

func init() {
	atomicNow = uint64(time.Now().Unix())
	go func() {
		for range time.Tick(time.Second) {
			atomic.AddUint64(&atomicNow, 1)
		}
	}()
}

var timeNow = func() uint64 {
	return atomic.LoadUint64(&atomicNow)
}

const (
	icmp = 1
	tcp  = 6
	udp  = 17
)

type ipPacket []byte

func (ip ipPacket) Version() int {
	if len(ip) > 0 {
		return int(ip[0] >> 4)
	}
	return 0
}

func (ip ipPacket) Protocol() int {
	if len(ip) > 9 && ip.Version() == 4 {
		return int(ip[9])
	}
	return 0
}

func (ip ipPacket) AddressesV4() (src, dst [4]byte) {
	if len(ip) >= 20 && ip.Version() == 4 {
		copy(src[:], ip[12:16])
		copy(dst[:], ip[16:20])
	}
	return
}

func (ip ipPacket) Body() []byte {
	if ip.Version() != 4 {
		return nil // No support for IPv6
	}
	n := int(ip[0] & 0x0f)
	if n < 5 || n > 15 || len(ip) < 4*n {
		return nil
	}
	return ip[4*n:]
}

type transportPacket []byte

func (tp transportPacket) Ports() (src, dst uint16) {
	if len(tp) >= 4 {
		src = binary.BigEndian.Uint16(tp[:2])
		dst = binary.BigEndian.Uint16(tp[2:])
	}
	return
}