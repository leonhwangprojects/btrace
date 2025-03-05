// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/unix"
)

var be = binary.BigEndian

type PktData struct {
	Addrs [8]byte
	Ports [4]byte
	Proto byte
	TCPFl byte
	Pad   [2]byte
}

func (p *PktData) zero() bool {
	return p.Addrs == [8]byte{}
}

func (p *PktData) saddr() netip.Addr {
	return netip.AddrFrom4(([4]byte)(p.Addrs[:4]))
}

func (p *PktData) daddr() netip.Addr {
	return netip.AddrFrom4(([4]byte)(p.Addrs[4:]))
}

func (p *PktData) sport() uint16 {
	return be.Uint16(p.Ports[:2])
}

func (p *PktData) dport() uint16 {
	return be.Uint16(p.Ports[2:])
}

func (p *PktData) tcpFlags() string {
	tcpFlags := []string{
		"FIN",
		"SYN",
		"RST",
		"PSH",
		"ACK",
		"URG",
		"ECE",
		"CWR",
	}

	var flags []string
	for i, flag := range tcpFlags {
		if p.TCPFl&(1<<uint(i)) != 0 {
			flags = append(flags, flag)
		}
	}

	return strings.Join(flags, "|")
}

func (p *PktData) repr() string {
	var sb strings.Builder

	switch p.Proto {
	case unix.IPPROTO_TCP:
		fmt.Fprintf(&sb, "%s:%d -> %s:%d (TCP:%s)", p.saddr(), p.sport(), p.daddr(), p.dport(), p.tcpFlags())

	case unix.IPPROTO_UDP:
		fmt.Fprintf(&sb, "%s:%d -> %s:%d (UDP)", p.saddr(), p.sport(), p.daddr(), p.dport())

	case unix.IPPROTO_ICMP:
		fmt.Fprintf(&sb, "%s -> %s (ICMP)", p.saddr(), p.daddr())

	default:
		return "..UNK.."
	}

	return sb.String()
}
