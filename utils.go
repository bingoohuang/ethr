// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	gLocalIP    = ""
	gPort       = uint16(12321)
	gPortStr    = ""
	gClientPort = uint16(0)
	gTOS        = uint8(0)
	gTTL        = uint8(0)
)

const (
	KILO = 1000
	MEGA = 1000 * KILO
	GIGA = 1000 * MEGA
	TERA = 1000 * GIGA
)

func numberToUnit(num uint64) string {
	unit, value := "", float64(num)

	switch {
	case num >= TERA:
		unit, value = "T", value/TERA
	case num >= GIGA:
		unit, value = "G", value/GIGA
	case num >= MEGA:
		unit, value = "M", value/MEGA
	case num >= KILO:
		unit, value = "K", value/KILO
	}

	result := strconv.FormatFloat(value, 'f', 2, 64)
	result = strings.TrimSuffix(result, ".00")
	return result + unit
}

func unitToNumber(s string) uint64 {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	i := strings.IndexFunc(s, unicode.IsLetter)

	if i == -1 {
		bytes, err := strconv.ParseFloat(s, 64)
		if err != nil || bytes <= 0 {
			return 0
		}
		return uint64(bytes)
	}

	bytesString, multiple := s[:i], s[i:]
	bytes, err := strconv.ParseFloat(bytesString, 64)
	if err != nil || bytes <= 0 {
		return 0
	}

	switch multiple {
	case "T", "TB", "TIB":
		return uint64(bytes * TERA)
	case "G", "GB", "GIB":
		return uint64(bytes * GIGA)
	case "M", "MB", "MIB":
		return uint64(bytes * MEGA)
	case "K", "KB", "KIB":
		return uint64(bytes * KILO)
	case "B":
		return uint64(bytes)
	default:
		return 0
	}
}

func bytesToRate(bytes uint64) string {
	return numberToUnit(bytes * 8)
}

func cpsToString(cps uint64) string {
	return numberToUnit(cps)
}

func ppsToString(pps uint64) string {
	return numberToUnit(pps)
}

func (t TestType) String() string {
	switch t {
	case Bandwidth:
		return "Bandwidth"
	case Cps:
		return "Connections/s"
	case Pps:
		return "Packets/s"
	case Latency:
		return "Latency"
	case Ping:
		return "Ping"
	case TraceRoute:
		return "TraceRoute"
	case MyTraceRoute:
		return "MyTraceRoute"
	default:
		return "Invalid"
	}
}

func durationToString(d time.Duration) string {
	if d < 0 {
		return d.String()
	}
	ud := uint64(d)
	val := float64(ud)
	unit := ""
	if ud < uint64(60*time.Second) {
		switch {
		case ud < uint64(time.Microsecond):
			unit = "ns"
		case ud < uint64(time.Millisecond):
			val = val / 1000
			unit = "us"
		case ud < uint64(time.Second):
			val = val / (1000 * 1000)
			unit = "ms"
		default:
			val = val / (1000 * 1000 * 1000)
			unit = "s"
		}

		result := strconv.FormatFloat(val, 'f', 3, 64)
		return result + unit
	}

	return d.String()
}

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	}
	return ""
}

func Tcp() string {
	switch ipVer {
	case iPv4:
		return "tcp4"
	case iPv6:
		return "tcp6"
	}
	return "tcp"
}

func Udp() string {
	switch ipVer {
	case iPv4:
		return "udp4"
	case iPv6:
		return "udp6"
	}
	return "udp"
}

func Icmp() string {
	switch ipVer {
	case iPv6:
		return "ip6:ipv6-icmp"
	default:
		return "ip4:icmp"
	}
}

func IcmpProto() int {
	if ipVer == iPv6 {
		return ICMPv6
	}
	return ICMPv4
}

func splitString(longString string, maxLen int) []string {
	splits := []string{}

	var l, r int
	for l, r = 0, maxLen; r < len(longString); l, r = r, r+maxLen {
		for !utf8.RuneStart(longString[r]) {
			r--
		}
		splits = append(splits, longString[l:r])
	}
	splits = append(splits, longString[l:])
	return splits
}

func truncateStringFromStart(str string, num int) string {
	s := str
	l := len(str)
	if l > num {
		if num > 3 {
			s = "..." + str[l-num+3:l]
		} else {
			s = str[l-num : l]
		}
	}
	return s
}

func truncateStringFromEnd(str string, num int) string {
	s := str
	l := len(str)
	if l > num {
		if num > 3 {
			s = str[0:num] + "..."
		} else {
			s = str[0:num]
		}
	}
	return s
}

func getFd(conn net.Conn) uintptr {
	var fd uintptr
	var rc syscall.RawConn
	var err error
	switch ct := conn.(type) {
	case *net.TCPConn:
		rc, err = ct.SyscallConn()
		if err != nil {
			return 0
		}
	case *net.UDPConn:
		rc, err = ct.SyscallConn()
		if err != nil {
			return 0
		}
	default:
		return 0
	}
	fn := func(s uintptr) {
		fd = s
	}
	rc.Control(fn)
	return fd
}

func SleepUntilNextWholeSecond() {
	t0 := time.Now()
	t1 := t0.Add(time.Second)
	res := t1.Round(time.Second)
	time.Sleep(time.Until(res))
}

func setTTL(fd uintptr, ttl int) {
	if ttl == 0 {
		return
	}
	if ipVer == iPv4 {
		setSockOptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	} else {
		setSockOptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	}
}

func setTOS(fd uintptr, tos int) {
	if tos == 0 {
		return
	}
	if ipVer == iPv4 {
		setSockOptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
	} else {
		SetTClass(fd, tos)
	}
}

func (p Protocol) dial(dialAddr string) (conn net.Conn, err error) {
	return p.dialEx(dialAddr, gLocalIP, gClientPort, int(gTTL), int(gTOS))
}

func (p Protocol) dialInc(dialAddr string, inc uint16) (conn net.Conn, err error) {
	if gClientPort == 0 {
		return p.dial(dialAddr)
	}

	return p.dialEx(dialAddr, gLocalIP, gClientPort+inc, int(gTTL), int(gTOS))
}

func (p Protocol) dialAll(dialAddr string) (conn net.Conn, err error) {
	return p.dialEx(dialAddr, gLocalIP, 0, int(gTTL), int(gTOS))
}

func (p Protocol) dialEx(dialAddr, localIP string, localPortNum uint16, ttl, tos int) (conn net.Conn, err error) {
	localAddr := fmt.Sprintf("%v:%v", localIP, localPortNum)
	var la net.Addr
	network := Tcp()
	switch p {
	case TCP:
		la, err = net.ResolveTCPAddr(network, localAddr)
	case UDP:
		network = Udp()
		la, err = net.ResolveUDPAddr(network, localAddr)
	default:
		ui.printDbg("Only TCP or UDP are allowed in dialEx")
		err = os.ErrInvalid
		return
	}
	if err != nil {
		ui.printErr("Unable to resolve TCP or UDP address. Error: %v", err)
		return
	}
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setTTL(fd, ttl)
				setTOS(fd, tos)
			})
		},
	}
	dialer.LocalAddr = la
	dialer.Timeout = time.Second
	conn, err = dialer.Dial(network, dialAddr)
	if err != nil {
		ui.printDbg("Dial Error: %v", err)
		return
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0)
	} else if uc, ok2 := conn.(*net.UDPConn); ok2 {
		if err := uc.SetWriteBuffer(4 * 1024 * 1024); err != nil {
			ui.printDbg("Failed to set ReadBuffer on UDP socket: %v", err)
		}
	}

	return
}

func lookupIP(server string) (net.IPAddr, string, error) {
	var ipAddr net.IPAddr
	var ipStr string

	ip := net.ParseIP(server)
	if ip != nil {
		ipAddr.IP = ip
		ipStr = server
		return ipAddr, ipStr, nil
	}

	ips, err := net.LookupIP(server)
	if err != nil {
		ui.printErr("Failed to lookup IP address for the server: %v. Error: %v", server, err)
		return ipAddr, ipStr, err
	}

	for _, ip := range ips {
		if ipVer.IsValid(ip) {
			ipAddr.IP = ip
			ipStr = ip.String()
			ui.printDbg("Resolved server: %v to IP address: %v\n", server, ip)
			return ipAddr, ipStr, nil
		}
	}
	ui.printErr("Unable to resolve the given server: %v to an IP address.", server)
	return ipAddr, ipStr, os.ErrNotExist
}

// This is a workaround to ensure we generate traffic at certain rate
// and stats are printed correctly. We ensure that current interval lasts
// 100ms after stats are printed, not perfect but workable.
func beginThrottle(totalBytesToSend uint64, bufferLen int) (start time.Time, waitTime time.Duration, bytesToSend int) {
	start = time.Now()
	waitTime = time.Until(lastStatsTime.Add(time.Second + 50*time.Millisecond))
	bytesToSend = bufferLen
	if totalBytesToSend > 0 && totalBytesToSend < uint64(bufferLen) {
		bytesToSend = int(totalBytesToSend)
	}
	return
}

func enforceThrottle(s time.Time, wt time.Duration, totalBytesToSend, oldSentBytes uint64, bufferLen int) (
	start time.Time, waitTime time.Duration, newSentBytes uint64, bytesToSend int,
) {
	start = s
	waitTime = wt
	newSentBytes = oldSentBytes
	bytesToSend = bufferLen
	if totalBytesToSend > 0 {
		remainingBytes := totalBytesToSend - oldSentBytes
		if remainingBytes > 0 {
			if remainingBytes < uint64(bufferLen) {
				bytesToSend = int(remainingBytes)
			}
		} else {
			timeTaken := time.Since(s)
			if timeTaken < wt {
				time.Sleep(wt - timeTaken)
			}
			start = time.Now()
			waitTime = time.Until(lastStatsTime.Add(time.Second + 50*time.Millisecond))
			newSentBytes = 0
			if totalBytesToSend < uint64(bufferLen) {
				bytesToSend = int(totalBytesToSend)
			}
		}
	}
	return
}

func If(b bool, s1, s2 string) string {
	if b {
		return s1
	}
	return s2
}
