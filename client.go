//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"net"
	"os"
	"os/signal"

	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	done       = 0
	timeout    = 1
	interrupt  = 2
	disconnect = 3
)

func handleInterrupt(toStop chan<- int) {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		toStop <- interrupt
	}()
}

func runDurationTimer(d time.Duration, toStop chan int) {
	go func() {
		if dSeconds := uint64(d.Seconds()); dSeconds == 0 {
			return
		}
		time.Sleep(d)
		// Sleep extra 200ms to ensure stats print for correct number of seconds.
		time.Sleep(200 * time.Millisecond)
		toStop <- timeout
	}()
}

func initClient(title string) {
	initClientUI(title)
}

func (t *test) handshakeWithServer(conn net.Conn) error {
	msg := createSynMsg(t.testID, t.clientParam)
	if err := msg.send(conn); err != nil {
		ui.printDbg("Failed to send SYN message to Ethr server. Error: %v", err)
		return err
	}
	if m := recvSessionMsg(conn); m.Type != Ack {
		ui.printDbg("Failed to receive ACK message from Ethr server. Error: %v", m)
		return os.ErrInvalid
	}
	return nil
}

func getServerIPPort(server string) (hostName, hostIP, port string, err error) {
	u, err := url.Parse(server)
	if err == nil && u.Hostname() != "" {
		hostName = u.Hostname()
		if u.Port() != "" {
			port = u.Port()
		} else {
			// Only implicitly derive port in External client mode.
			if gIsExternalClient {
				switch u.Scheme {
				case "http":
					port = "80"
				case "https":
					port = "443"
				}
			}
		}
	} else {
		if hostName, port, err = net.SplitHostPort(server); err != nil {
			hostName = server
		}
	}
	_, hostIP, err = lookupIP(hostName)
	return hostName, hostIP, port, err
}

func runClient(testID TestID, title string, clientParam clientParam, server string) {
	initClient(title)
	hostName, hostIP, port, err := getServerIPPort(server)
	if err != nil {
		return
	}
	ip := net.ParseIP(hostIP)
	if ip == nil {
		return
	}

	if ip.To4() != nil {
		ipVer = iPv4
	} else {
		ipVer = iPv6
	}

	if gIsExternalClient {
		if testID.Protocol != ICMP && port == "" {
			ui.printErr("In external mode, port cannot be empty for TCP tests.")
			return
		}
	} else {
		if port != "" {
			ui.printErr("In client mode, port (%s) cannot be specified in destination (%s).", port, server)
			ui.printMsg("Hint: Use external mode (-x).")
			return
		}
		port = gPortStr
	}
	ui.printMsg("Using destination: %s, ip: %s, port: %s", hostName, hostIP, port)
	t, err := newTest(hostIP, testID, clientParam)
	if err != nil {
		ui.printErr("Failed to create the new t.")
		return
	}
	t.remoteAddr = server
	t.remoteIP = hostIP
	t.remotePort = port
	if testID.Protocol == ICMP {
		t.dialAddr = hostIP
	} else {
		t.dialAddr = fmt.Sprintf("[%s]:%s", hostIP, port)
	}
	t.runTest()
}

func (t *test) runTest() {
	toStop := make(chan int, 16)
	startStatsTimer()
	gap := t.clientParam.Gap
	duration := t.clientParam.Duration
	runDurationTimer(duration, toStop)
	t.isActive = true
	switch t.testID.Protocol {
	case TCP:
		switch t.testID.Type {
		case Bandwidth:
			t.tcpRunBandwidthTest(toStop)
		case Latency:
			go t.runTCPLatencyTest(gap, toStop)
		case Cps:
			go t.tcpRunCpsTest()
		case Ping:
			go t.clientRunPingTest(gap, t.clientParam.WarmupCount)
		case TraceRoute:
			VerifyPermissionForTest(t.testID)
			go t.tcpRunTraceRoute(gap, toStop)
		case MyTraceRoute:
			VerifyPermissionForTest(t.testID)
			go t.tcpRunMyTraceRoute(gap, toStop)
		}
	case UDP:
		switch t.testID.Type {
		case Bandwidth, Pps:
			t.runUDPBandwidthAndPpsTest()
		}
	case ICMP:
		VerifyPermissionForTest(t.testID)
		switch t.testID.Type {
		case Ping:
			go t.clientRunPingTest(gap, t.clientParam.WarmupCount)
		case TraceRoute:
			go t.icmpRunTraceRoute(gap, toStop)
		case MyTraceRoute:
			go t.icmpRunMyTraceRoute(gap, toStop)
		}
	}
	handleInterrupt(toStop)
	reason := <-toStop
	stopStatsTimer()
	close(t.done)
	if t.testID.Type == Ping {
		time.Sleep(2 * time.Second)
	}
	switch reason {
	case done:
		ui.printMsg("Ethr done, measurement complete.")
	case timeout:
		ui.printMsg("Ethr done, duration: " + duration.String() + ".")
		ui.printMsg("Hint: Use -d parameter to change duration of the t.")
	case interrupt:
		ui.printMsg("Ethr done, received interrupt signal.")
	case disconnect:
		ui.printMsg("Ethr done, connection terminated.")
	}
	return
}

func (t *test) tcpRunBandwidthTest(toStop chan int) {
	var wg sync.WaitGroup
	t.tcpRunBandwidthTestThreads(&wg)
	go func(wg *sync.WaitGroup) {
		wg.Wait()
		toStop <- disconnect
	}(&wg)
}

func (t *test) tcpRunBandwidthTestThreads(wg *sync.WaitGroup) {
	for th := uint32(0); th < t.clientParam.NumThreads; th++ {
		conn, err := TCP.dialInc(t.dialAddr, uint16(th))
		if err != nil {
			ui.printErr("Error dialing connection: %v", err)
			continue
		}
		if err := t.handshakeWithServer(conn); err != nil {
			ui.printErr("Failed in handshake with the server. Error: %v", err)
			conn.Close()
			continue
		}
		wg.Add(1)
		go t.runTCPBandwidthTestHandler(conn, wg)
	}
}

func (t *test) runTCPBandwidthTestHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()
	ec := t.newConn(conn)
	rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
	lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
	ui.printMsg("[%3d] local %s port %s connected to %s port %s",
		ec.fd, lserver, lport, rserver, rport)
	size := t.clientParam.BufferSize
	buff := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		buff[i] = byte(i)
	}
	totalBytesToSend := t.clientParam.BwRate
	sentBytes := uint64(0)
	start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, len(buff))
	for {
		select {
		case <-t.done:
			return
		default:
			n := 0
			var err error = nil
			if t.clientParam.Reverse {
				n, err = conn.Read(buff)
			} else {
				n, err = conn.Write(buff[:bytesToSend])
			}
			if err != nil {
				ui.printDbg("Error sending/receiving data on a connection for bandwidth test: %v", err)
				return
			}
			atomic.AddUint64(&ec.bw, uint64(n))
			atomic.AddUint64(&t.testResult.bw, uint64(n))
			if !t.clientParam.Reverse {
				sentBytes += uint64(n)
				start, waitTime, sentBytes, bytesToSend = enforceThrottle(
					start, waitTime, totalBytesToSend, sentBytes, len(buff))
			}
		}
	}
}

func (t *test) runTCPLatencyTest(g time.Duration, toStop chan int) {
	ui.printMsg("Running latency test: %v, %v", t.clientParam.RttCount, t.clientParam.BufferSize)
	conn, err := TCP.dial(t.dialAddr)
	if err != nil {
		ui.printErr("Error dialing the latency connection: %v", err)
		return
	}
	defer conn.Close()
	if err := t.handshakeWithServer(conn); err != nil {
		ui.printErr("Failed in handshake with the server. Error: %v", err)
		return
	}
	ui.emitLatencyHdr()
	buffSize := t.clientParam.BufferSize
	buff := make([]byte, buffSize)
	for i := uint32(0); i < buffSize; i++ {
		buff[i] = byte(i)
	}
	blen := len(buff)
	rttCount := t.clientParam.RttCount
	latencyNumbers := make([]time.Duration, rttCount)
	for {
		select {
		case <-t.done:
			return
		default:
			t0 := time.Now()
			for i := uint32(0); i < rttCount; i++ {
				s1 := time.Now()
				if n, err := conn.Write(buff); err != nil || n < blen {
					ui.printDbg("Error sending/receiving data on a connection for latency t: %v", err)
					toStop <- disconnect
					continue
				}
				if _, err := io.ReadFull(conn, buff); err != nil {
					ui.printDbg("Error sending/receiving data on a connection for latency t: %v", err)
					toStop <- disconnect
					continue
				}
				e2 := time.Since(s1)
				latencyNumbers[i] = e2
			}
			// TODO temp code, fix it better, this is to allow server to do
			// server side latency measurements as well.
			_, _ = conn.Write(buff)
			t.calcAndPrintLatency(rttCount, latencyNumbers)
			if t1 := time.Since(t0); t1 < g {
				time.Sleep(g - t1)
			}
		}
	}
}

func (t *test) calcAndPrintLatency(rttCount uint32, latencyNumbers []time.Duration) {
	sum := int64(0)
	for _, d := range latencyNumbers {
		sum += d.Nanoseconds()
	}
	elapsed := time.Duration(sum / int64(rttCount))
	sort.SliceStable(latencyNumbers, func(i, j int) bool {
		return latencyNumbers[i] < latencyNumbers[j]
	})
	//
	// Special handling for rttCount == 1. This prevents negative index
	// in the latencyNumber index. The other option is to use
	// roundUpToZero() but that is more expensive.
	//
	rttCountFixed := rttCount
	if rttCountFixed == 1 {
		rttCountFixed = 2
	}
	avg := elapsed
	min := latencyNumbers[0]
	max := latencyNumbers[rttCount-1]
	p50 := latencyNumbers[((rttCountFixed*50)/100)-1]
	p90 := latencyNumbers[((rttCountFixed*90)/100)-1]
	p95 := latencyNumbers[((rttCountFixed*95)/100)-1]
	p99 := latencyNumbers[((rttCountFixed*99)/100)-1]
	p999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.9)/100)-1)]
	p9999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.99)/100)-1)]
	ui.emitLatencyResults(
		t.session.remoteIP,
		t.testID.Protocol.String(),
		avg, min, max, p50, p90, p95, p99, p999, p9999)
}

func (t *test) tcpRunCpsTest() {
	for th := uint32(0); th < t.clientParam.NumThreads; th++ {
		go func(th uint32) {
			for {
				select {
				case <-t.done:
					return
				default:
					if conn, err := TCP.dialAll(t.dialAddr); err == nil {
						atomic.AddUint64(&t.testResult.cps, 1)
						if c, ok := conn.(*net.TCPConn); ok {
							c.SetLinger(0)
						}
						conn.Close()
					} else {
						ui.printDbg("Unable to dial TCP connection to %s, error: %v", t.dialAddr, err)
					}
				}
			}
		}(th)
	}
}

func (t *test) clientRunPingTest(g time.Duration, warmupCount uint32) {
	// TODO: Override NumThreads for now, fix it later to support parallel threads.
	t.clientParam.NumThreads = 1
	for th := uint32(0); th < t.clientParam.NumThreads; th++ {
		go func() {
			var sent, rcvd, lost uint32
			warmupText := "[warmup] "
			latencyNumbers := make([]time.Duration, 0)
			for {
				select {
				case <-t.done:
					t.printConnectionLatencyResults(t.dialAddr, sent, rcvd, lost, latencyNumbers)
					return
				default:
					t0 := time.Now()
					if warmupCount > 0 {
						warmupCount--
						t.clientRunPing(warmupText)
					} else {
						sent++
						latency, err := t.clientRunPing("")
						if err == nil {
							rcvd++
							latencyNumbers = append(latencyNumbers, latency)
						} else {
							lost++
						}
					}
					if rcvd >= 1000 {
						t.printConnectionLatencyResults(t.dialAddr, sent, rcvd, lost, latencyNumbers)
						latencyNumbers = make([]time.Duration, 0)
						sent, rcvd, lost = 0, 0, 0
					}
					if t1 := time.Since(t0); t1 < g {
						time.Sleep(g - t1)
					}
				}
			}
		}()
	}
}

func (t *test) clientRunPing(prefix string) (time.Duration, error) {
	if t.testID.Protocol == TCP {
		return t.tcpRunPing(prefix)
	}
	return t.icmpRunPing(prefix)
}

func (t *test) tcpRunPing(prefix string) (timeTaken time.Duration, err error) {
	t0 := time.Now()
	conn, err := TCP.dial(t.dialAddr)
	if err != nil {
		ui.printMsg("[tcp] %sConnection to %s: Timed out (%v)", prefix, t.dialAddr, err)
		return
	}
	timeTaken = time.Since(t0)
	rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
	lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
	ui.printMsg("[tcp] %sConnection from [%s]:%s to [%s]:%s: %s",
		prefix, lserver, lport, rserver, rport, durationToString(timeTaken))
	tcpconn, ok := conn.(*net.TCPConn)
	if ok {
		tcpconn.SetLinger(0)
	}
	conn.Close()
	return
}

func (t *test) printConnectionLatencyResults(server string, sent, rcvd, lost uint32, latencyNumbers []time.Duration) {
	fmt.Println("-----------------------------------------------------------------------------------------")
	ui.printMsg("TCP connect statistics for %s:", server)
	ui.printMsg("  Sent = %d, Received = %d, Lost = %d", sent, rcvd, lost)
	if rcvd > 0 {
		ui.emitLatencyHdr()
		t.calcAndPrintLatency(rcvd, latencyNumbers)
		fmt.Println("-----------------------------------------------------------------------------------------")
	}
}

func (t *test) tcpRunTraceRoute(gap time.Duration, toStop chan int) {
	t.tcpRunTraceRouteInternal(gap, toStop, false)
}

func (t *test) tcpRunMyTraceRoute(gap time.Duration, toStop chan int) {
	t.tcpRunTraceRouteInternal(gap, toStop, true)
}

func (t *test) tcpRunTraceRouteInternal(gap time.Duration, toStop chan int, mtrMode bool) {
	gHop = make([]hopData, gMaxHops)
	err := t.tcpDiscoverHops(mtrMode)
	if err != nil {
		ui.printErr("Destination %s is not responding to TCP connection.", t.session.remoteIP)
		ui.printErr("Terminating tracing...")
		toStop <- interrupt
		return
	}
	if !mtrMode {
		toStop <- done
		return
	}
	for i := 0; i < gCurHops; i++ {
		if gHop[i].addr != "" {
			go t.tcpProbeHop(gap, i)
		}
	}
}

func (t *test) tcpProbeHop(gap time.Duration, hop int) {
	seq := 0
	for {
		select {
		case <-t.done:
			return
		default:
			t0 := time.Now()
			_, _ = t.tcpProbe(hop+1, gHop[hop].addr, &gHop[hop])
			seq++
			t1 := time.Since(t0)
			if t1 < gap {
				time.Sleep(gap - t1)
			}
		}
	}
}

func (t *test) tcpDiscoverHops(mtrMode bool) error {
	ui.printMsg("Tracing route to %s over %d hops:", t.session.remoteIP, gMaxHops)
	for i := 0; i < gMaxHops; i++ {
		var hopData hopData
		err, isLast := t.tcpProbe(i+1, "", &hopData)
		if err == nil {
			hopData.name, hopData.fullName = lookupHopName(hopData.addr)
		}
		if hopData.addr != "" {
			if mtrMode {
				ui.printMsg("%2d.|--%s", i+1, hopData.addr+" ["+hopData.fullName+"]")
			} else {
				ui.printMsg("%2d.|--%-70s %s", i+1, hopData.addr+" ["+hopData.fullName+"]", durationToString(hopData.last))
			}
		} else {
			ui.printMsg("%2d.|--%s", i+1, "???")
		}
		copyInitialHopData(i, hopData)
		if isLast {
			gCurHops = i + 1
			return nil
		}
	}
	return os.ErrNotExist
}

func (t *test) tcpProbe(hop int, hopIP string, hopData *hopData) (error, bool) {
	isLast := false
	c, err := IcmpNewConn(t.remoteIP)
	if err != nil {
		ui.printErr("Failed to create ICMP connection. Error: %v", err)
		return err, isLast
	}
	defer c.Close()
	localPortNum := uint16(8888)
	if gClientPort != 0 {
		localPortNum = gClientPort
	}
	localPortNum += uint16(hop)
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:], localPortNum)
	remotePortNum, err := strconv.ParseUint(t.remotePort, 10, 16)
	binary.BigEndian.PutUint16(b[2:], uint16(remotePortNum))
	peerAddrChan := make(chan string)
	endTimeChan := make(chan time.Time)
	go func() {
		peerAddr, _, _ := icmpRecvMsg(c, TCP, time.Second*2, hopIP, b, nil, 0)
		endTimeChan <- time.Now()
		peerAddrChan <- peerAddr
	}()
	startTime := time.Now()
	conn, err := TCP.dialEx(t.dialAddr, gLocalIP, localPortNum, hop, int(gTOS))
	if err != nil {
		ui.printDbg("Failed to Dial the connection. Error: %v", err)
	} else {
		conn.Close()
	}
	hopData.sent++
	peerAddr := ""
	endTime := time.Now()
	if err == nil {
		isLast = true
		peerAddr = t.remoteIP
	} else {
		endTime = <-endTimeChan
		peerAddr = <-peerAddrChan
	}
	elapsed := endTime.Sub(startTime)
	if peerAddr == "" || (hopIP != "" && peerAddr != hopIP) {
		hopData.lost++
		ui.printDbg("Neither connection completed, nor ICMP TTL exceeded received.")
		return os.ErrNotExist, isLast
	}
	genHopData(hopData, peerAddr, elapsed)
	return nil, isLast
}

type hopData struct {
	addr     string
	sent     uint32
	rcvd     uint32
	lost     uint32
	last     time.Duration
	best     time.Duration
	worst    time.Duration
	total    time.Duration
	name     string
	fullName string
}

var gMaxHops = 30
var gCurHops int
var gHop []hopData

func (t *test) icmpRunPing(prefix string) (time.Duration, error) {
	dstIPAddr, _, err := lookupIP(t.dialAddr)
	if err != nil {
		return time.Second, err
	}

	var hopData hopData
	err, isLast := t.icmpProbe(dstIPAddr, time.Second, "", &hopData, 254, 255)
	if err != nil {
		ui.printMsg("[icmp] %sPing to %s: %v", prefix, t.dialAddr, err)
		return time.Second, err
	}
	if !isLast {
		ui.printMsg("[icmp] %sPing to %s: %s",
			prefix, t.dialAddr, "Non-EchoReply Received.")
		return time.Second, os.ErrNotExist
	}
	ui.printMsg("[icmp] %sPing to %s: %s",
		prefix, t.dialAddr, durationToString(hopData.last))
	return hopData.last, nil
}

func (t *test) icmpRunTraceRoute(gap time.Duration, toStop chan int) {
	t.icmpRunTraceRouteInternal(gap, toStop, false)
}

func (t *test) icmpRunMyTraceRoute(gap time.Duration, toStop chan int) {
	t.icmpRunTraceRouteInternal(gap, toStop, true)
}

func (t *test) icmpRunTraceRouteInternal(gap time.Duration, toStop chan int, mtrMode bool) {
	gHop = make([]hopData, gMaxHops)
	dstIPAddr, _, err := lookupIP(t.session.remoteIP)
	if err != nil {
		toStop <- interrupt
		return
	}
	if err = t.icmpDiscoverHops(dstIPAddr, mtrMode); err != nil {
		ui.printErr("Destination %s is not responding to ICMP Echo.", t.session.remoteIP)
		ui.printErr("Terminating tracing...")
		toStop <- interrupt
		return
	}
	if !mtrMode {
		toStop <- done
		return
	}
	for i := 0; i < gCurHops; i++ {
		if gHop[i].addr != "" {
			go icmpProbeHop(t, gap, i, dstIPAddr)
		}
	}
}

func copyInitialHopData(hop int, hopData hopData) {
	gHop[hop].addr = hopData.addr
	gHop[hop].best = hopData.last
	gHop[hop].name = hopData.name
	gHop[hop].fullName = hopData.fullName
}

func genHopData(hopData *hopData, peerAddr string, elapsed time.Duration) {
	hopData.addr = peerAddr
	hopData.last = elapsed
	if hopData.best > elapsed {
		hopData.best = elapsed
	}
	if hopData.worst < elapsed {
		hopData.worst = elapsed
	}
	hopData.total += elapsed
	hopData.rcvd++
}

func lookupHopName(addr string) (string, string) {
	name := ""
	tname := ""
	if addr == "" {
		return tname, name
	}
	names, err := net.LookupAddr(addr)
	if err == nil && len(names) > 0 {
		name = names[0]
		sz := len(name)

		if sz > 0 && name[sz-1] == '.' {
			name = name[:sz-1]
		}
		tname = truncateStringFromEnd(name, 16)
	}
	return tname, name
}

func (t *test) icmpDiscoverHops(dstIPAddr net.IPAddr, mtrMode bool) error {
	if t.session.remoteIP == dstIPAddr.String() {
		ui.printMsg("Tracing route to %s over %d hops:", t.session.remoteIP, gMaxHops)
	} else {
		ui.printMsg("Tracing route to %s (%s) over %d hops:", t.session.remoteIP, dstIPAddr.String(), gMaxHops)
	}
	for i := 0; i < gMaxHops; i++ {
		var hopData hopData
		err, isLast := t.icmpProbe(dstIPAddr, time.Second*2, "", &hopData, i, 1)
		if err == nil {
			hopData.name, hopData.fullName = lookupHopName(hopData.addr)
		}
		if hopData.addr != "" {
			if mtrMode {
				ui.printMsg("%2d.|--%s", i+1, hopData.addr+" ["+hopData.fullName+"]")
			} else {
				ui.printMsg("%2d.|--%-70s %s", i+1, hopData.addr+" ["+hopData.fullName+"]", durationToString(hopData.last))
			}
		} else {
			ui.printMsg("%2d.|--%s", i+1, "???")
		}
		copyInitialHopData(i, hopData)
		if isLast {
			gCurHops = i + 1
			return nil
		}
	}
	return os.ErrNotExist
}

func icmpProbeHop(t *test, gap time.Duration, hop int, dstIPAddr net.IPAddr) {
	seq := 0
	for {
		select {
		case <-t.done:
			return
		default:
			t0 := time.Now()
			err, _ := t.icmpProbe(dstIPAddr, time.Second, gHop[hop].addr, &gHop[hop], hop, seq)
			if err == nil {
			}
			seq++
			t1 := time.Since(t0)
			if t1 < gap {
				time.Sleep(gap - t1)
			}
		}
	}
}

func (t *test) icmpProbe(dstIPAddr net.IPAddr, icmpTimeout time.Duration, hopIP string, hopData *hopData, hop, seq int) (error, bool) {
	isLast := false
	echoMsg := fmt.Sprintf("Hello: Ethr - %v", hop)

	c, err := IcmpNewConn(t.remoteIP)
	if err != nil {
		ui.printErr("Failed to create ICMP connection. Error: %v", err)
		return err, isLast
	}
	defer c.Close()
	start, wb, err := icmpSendMsg(c, dstIPAddr, hop, seq, echoMsg, icmpTimeout)
	if err != nil {
		return err, isLast
	}
	hopData.sent++
	neededSeq := hop<<8 | seq
	peerAddr, isLast, err := icmpRecvMsg(c, ICMP, icmpTimeout, hopIP, wb[4:8], []byte(echoMsg), neededSeq)
	if err != nil {
		hopData.lost++
		ui.printDbg("Failed to receive ICMP reply packet. Error: %v", err)
		return err, isLast
	}
	elapsed := time.Since(start)
	genHopData(hopData, peerAddr, elapsed)
	return nil, isLast
}

func icmpSetTTL(c net.PacketConn, ttl int) error {
	if ipVer == iPv4 {
		cIPv4 := ipv4.NewPacketConn(c)
		return cIPv4.SetTTL(ttl)
	} else if ipVer == iPv6 {
		cIPv6 := ipv6.NewPacketConn(c)
		return cIPv6.SetHopLimit(ttl)
	}
	return os.ErrInvalid
}

func icmpSetTOS(c net.PacketConn, tos int) error {
	if tos == 0 {
		return nil
	}
	err := os.ErrInvalid
	if ipVer == iPv4 {
		cIPv4 := ipv4.NewPacketConn(c)
		err = cIPv4.SetTOS(tos)
	} else if ipVer == iPv6 {
		cIPv6 := ipv6.NewPacketConn(c)
		err = cIPv6.SetTrafficClass(tos)
	}
	return err
}

func icmpSendMsg(c net.PacketConn, dstIPAddr net.IPAddr, hop, seq int, body string, timeout time.Duration) (time.Time, []byte, error) {
	start := time.Now()
	err := icmpSetTTL(c, hop+1)
	if err != nil {
		ui.printErr("Failed to set TTL. Error: %v", err)
		return start, nil, err
	}
	icmpSetTOS(c, int(gTOS))

	err = c.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		ui.printErr("Failed to set Deadline. Error: %v", err)
		return start, nil, err
	}

	pid := os.Getpid() & 0xffff
	pid = 9999
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: pid, Seq: hop<<8 | seq,
			Data: []byte(body),
		},
	}
	if ipVer == iPv6 {
		wm.Type = ipv6.ICMPTypeEchoRequest
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		ui.printErr("Failed to Marshal data. Error: %v", err)
		return start, nil, err
	}
	start = time.Now()
	if _, err := c.WriteTo(wb, &dstIPAddr); err != nil {
		ui.printErr("Failed to send ICMP data. Error: %v", err)
		return start, nil, err
	}
	return start, wb, nil
}

func icmpRecvMsg(c net.PacketConn, proto Protocol, timeout time.Duration, neededPeer string, neededSig, neededIcmpBody []byte, neededIcmpSeq int) (string, bool, error) {
	peerAddr := ""
	isLast := false
	err := c.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		ui.printErr("Failed to set Deadline. Error: %v", err)
		return peerAddr, isLast, err
	}
	for {
		peerAddr = ""
		b := make([]byte, 1500)
		n, peer, err := c.ReadFrom(b)
		if err != nil {
			if proto == ICMP {
				// In case of non-ICMP TraceRoute, it is expected that no packet is received
				// in some case, e.g. when packet reach final hop and TCP connection establishes.
				ui.printDbg("Failed to receive ICMP packet. Error: %v", err)
			}
			return peerAddr, isLast, err
		}
		if n == 0 {
			continue
		}
		ui.printDbg("Packet:\n%s", hex.Dump(b[:n]))
		ui.printDbg("Finding Pattern\n%v", hex.Dump(neededSig[:4]))
		peerAddr = peer.String()
		if neededPeer != "" && peerAddr != neededPeer {
			ui.printDbg("Matching peer is not found.")
			continue
		}
		icmpMsg, err := icmp.ParseMessage(IcmpProto(), b[:n])
		if err != nil {
			ui.printDbg("Failed to parse ICMP message: %v", err)
			continue
		}
		switch icmpMsg.Type {
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			body := icmpMsg.Body.(*icmp.TimeExceeded).Data
			index := bytes.Index(body, neededSig[:4])
			if index > 0 {
				switch proto {
				case TCP:
					ui.printDbg("Found correct ICMP error message. PeerAddr: %v", peerAddr)
					return peerAddr, isLast, nil
				case ICMP:
					if index < 4 {
						ui.printDbg("Incorrect length of ICMP message.")
						continue
					}

					switch msg, _ := icmp.ParseMessage(IcmpProto(), body[index-4:]); msg.Body.(type) {
					case *icmp.Echo:
						seq := msg.Body.(*icmp.Echo).Seq
						if seq == neededIcmpSeq {
							return peerAddr, isLast, nil
						}
					default:
						// Ignore as this is not the right ICMP packet.
						ui.printDbg("Unable to recognize packet.")
					}
				}
			} else {
				ui.printDbg("Pattern %v not found.", hex.Dump(neededSig[:4]))
			}
		}

		if proto == ICMP && (icmpMsg.Type == ipv4.ICMPTypeEchoReply || icmpMsg.Type == ipv6.ICMPTypeEchoReply) {
			_ = icmpMsg.Body.(*icmp.Echo)
			b, _ := icmpMsg.Body.Marshal(1)
			if string(b[4:]) != string(neededIcmpBody) {
				continue
			}
			isLast = true
			return peerAddr, isLast, nil
		}
	}
}

func (t *test) runUDPBandwidthAndPpsTest() {
	for th := uint32(0); th < t.clientParam.NumThreads; th++ {
		go func(th uint32) {
			size := t.clientParam.BufferSize
			buff := make([]byte, size)
			conn, err := UDP.dialInc(t.dialAddr, uint16(th))
			if err != nil {
				ui.printDbg("Unable to dial UDP, error: %v", err)
				return
			}
			defer conn.Close()
			ec := t.newConn(conn)
			rserver, rport, _ := net.SplitHostPort(conn.RemoteAddr().String())
			lserver, lport, _ := net.SplitHostPort(conn.LocalAddr().String())
			ui.printMsg("[%3d] local %s port %s connected to %s port %s",
				ec.fd, lserver, lport, rserver, rport)
			bufferLen := len(buff)
			totalBytesToSend := t.clientParam.BwRate
			sentBytes := uint64(0)
			start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)
			for {
				select {
				case <-t.done:
					return
				default:
					n, err := conn.Write(buff[:bytesToSend])
					if err != nil {
						ui.printDbg("%v", err)
						continue
					}
					if n < bytesToSend {
						ui.printDbg("Partial write: %d", n)
						continue
					}
					atomic.AddUint64(&ec.bw, uint64(n))
					atomic.AddUint64(&ec.pps, 1)
					atomic.AddUint64(&t.testResult.bw, uint64(n))
					atomic.AddUint64(&t.testResult.pps, 1)
					if !t.clientParam.Reverse {
						sentBytes += uint64(n)
						start, waitTime, sentBytes, bytesToSend = enforceThrottle(
							start, waitTime, totalBytesToSend, sentBytes, bufferLen)
					}
				}
			}
		}(th)
	}
}
