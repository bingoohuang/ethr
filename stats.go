//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"sort"
	"time"
)

type netStat struct {
	netDevStats []netDevStat
	tcpStats    TCPStat
}

type netDevStat struct {
	interfaceName string
	rxBytes       uint64
	txBytes       uint64
	rxPkts        uint64
	txPkts        uint64
}

type TCPStat struct {
	segRetrans uint64
}

func getNetworkStats() netStat {
	stats := &netStat{}
	getNetDevStats(stats)

	sort.SliceStable(stats.netDevStats, func(i, j int) bool {
		return stats.netDevStats[i].interfaceName < stats.netDevStats[j].interfaceName
	})
	getTCPStats(stats)

	return *stats
}

func adjust(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}

	return cur + ^uint64(0) - prev
}

func getNetDevStatDiff(cur netDevStat, prev netStat, seconds uint64) netDevStat {
	for _, p := range prev.netDevStats {
		if p.interfaceName == cur.interfaceName {
			cur.rxBytes = adjust(cur.rxBytes, p.rxBytes)
			cur.txBytes = adjust(cur.txBytes, p.txBytes)
			cur.rxPkts = adjust(cur.rxPkts, p.rxPkts)
			cur.txPkts = adjust(cur.txPkts, p.txPkts)
			break
		}
	}
	cur.rxBytes /= seconds
	cur.txBytes /= seconds
	cur.rxPkts /= seconds
	cur.txPkts /= seconds
	return cur
}

var statsEnabled bool

func startStatsTimer() {
	if statsEnabled {
		return
	}

	// In an ideal setup, client and server should print stats at the same time.
	// However, instead of building a whole time synchronization mechanism, a
	// hack is used that starts stat at a second granularity. This is done on
	// both client and sever, and as long as both client & server have time
	// synchronized e.g. with a time server, both would print stats of the running
	// test at _almost_ the same time.
	SleepUntilNextWholeSecond()

	lastStatsTime = time.Now()
	ticker := time.NewTicker(time.Second)
	statsEnabled = true
	go func() {
		for statsEnabled {
			select {
			case <-ticker.C:
				emitStats()
			}
		}
		ticker.Stop()
		return
	}()
}

func stopStatsTimer() {
	statsEnabled = false
}

var lastStatsTime = time.Now()

func emitStats() {
	d := time.Since(lastStatsTime)
	lastStatsTime = time.Now()
	seconds := int64(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	ui.emitTestResultBegin()
	emitTestResults(uint64(seconds))
	ui.emitTestResultEnd()
	ui.emitStats(getNetworkStats())
	ui.paint(uint64(seconds))
}

func emitTestResults(s uint64) {
	gSessionLock.RLock()
	defer gSessionLock.RUnlock()
	for _, k := range gSessionKeys {
		v := gSessions[k]
		ui.emitTestResult(v, TCP, s)
		ui.emitTestResult(v, UDP, s)
		ui.emitTestResult(v, ICMP, s)
	}
}
