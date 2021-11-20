//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	defaultLogFileName         = "./ethrs.log for server, ./ethrc.log for client"
	latencyDefaultBufferLenStr = "1B"
	defaultBufferLenStr        = "16KB"
)

var (
	AppVersion   = "Unknown"
	BuildTime    = "Unknown"
	GitCommit    = "Unknown"
	GoVersion    = "Unknown"
	loggingLevel = LogLevelInfo
	argIf        string
)

func main() {
	fmt.Println("\nEthr: Comprehensive Network Performance Measurement Tool (Version: " + AppVersion + ", Build: " + BuildTime + ", GitCommit: " + GitCommit + ", GoVersion:" + GoVersion + ")")
	fmt.Println("Maintainer: Pankaj Garg (ipankajg @ LinkedIn | GitHub | Gmail | Twitter)")
	fmt.Println("")

	// Set GOMAXPROCS to 1024 as running large number of goroutines that send
	// data in a tight loop over network is resulting in unfair time allocation
	// across goroutines causing starvation of many TCP connections. Using a
	// higher number of threads via GOMAXPROCS solves this problem.
	runtime.GOMAXPROCS(1024)

	// Common
	flag.Usage = func() { ethrUsage() }
	noOutput := flagBool("no", false, "", "Disable logging to file. Logging to file is enabled by default.")
	outputFile := flagString("o", defaultLogFileName, "<filename>", "Name of log file. By default, following file names are used:",
		"Server mode: 'ethrs.log'",
		"Client mode: 'ethrc.log'")
	debug := flagBool("debug", false, "", "Enable debug information in logging output.")
	use4 := flagBool("4", false, "", "Use only IP v4 version")
	use6 := flagBool("6", false, "", "Use only IP v6 version")
	port := flagInt("port", 12321, "<number>", "Use specified port number for TCP & UDP tests.", "Default: 12321")
	ip := flagString("ip", "", "<string>", "Bind to specified local IP address for TCP & UDP tests.",
		"This must be a valid IPv4 or IPv6 address.",
		"Default: <empty> - Any IP")
	// Server
	isServer := flagBool("s", true, "", "Run in server mode.")
	showUI := flagBool("ui", false, "", "Show output in text UI.")
	// Client & External Client
	clientDest := flagString("c", "", "<server>", "Run in client mode and connect to <server>.",
		"Server is specified using name, FQDN or IP address.")
	bufLenStr := flagString("l", "", "<length>",
		"Length of buffer (in Bytes) to use (format: <num>[KB | MB | GB])",
		"Only valid for Bandwidth tests. Max 1GB.", "Default: 16KB")
	bwRateStr := flagString("b", "", "<rate>",
		"Transmit only Bits per second (format: <num>[K | M | G])",
		"Only valid for Bandwidth tests. Default: 0 - Unlimited",
		"Examples: 100 (100bits/s), 1M (1Mbits/s).")
	cport := flagInt("cport", 0, "<number>",
		"Use specified local port number in client for TCP & UDP tests.",
		"Default: 0 - Ephemeral Port")
	duration := flagDuration("d", 10*time.Second, "<duration>",
		"Duration for the test (format: <num>[ms | s | m | h]",
		"0: Run forever", "Default: 10s")
	gap := flagDuration("g", time.Second, "<gap>",
		"Time interval between successive measurements (format: <num>[ms | s | m | h]",
		"Only valid for latency, ping and traceRoute tests.", "0: No gap", "Default: 1s")
	iterCount := flagInt("i", 1000, "<iterations>",
		"Number of round trip iterations for each latency measurement.",
		"Only valid for latency testing.", "Default: 1000")
	ncs := flagBool("ncs", false, "",
		"No per Connection Stats would be printed if this flag is specified.",
		"This is useful to suppress verbose logging when large number of",
		"connections are used as specified by -n option for Bandwidth tests.")
	protocol := flagString("p", "tcp", "")
	reverse := flagBool("r", false, "", "For Bandwidth tests, receive data from server.")
	testTypePtr := flagString("t", "", "")
	tos := flagInt("tos", 0, "", "Specifies 8-bit value to use in IPv4 TOS field or IPv6 Traffic Class field.")
	title := flagString("T", "", "<string>", "Use the given title in log files for logging results.", "Default: <empty>")
	thCount := flagInt("n", 1, "<number>", "Number of Parallel Sessions (and Threads).", "0: Equal to number of CPUs", "Default: 1")
	wc := flagInt("w", 1, "<number>", "Use specified number of iterations for warmup.", "Default: 1")
	xClientDest := flagString("x", "", "<destination>", "Run in external client mode and connect to <destination>.",
		"<destination> is specified in URL or Host:Port format.",
		"For URL, if port is not specified, it is assumed to be 80 for http and 443 for https.",
		"Example: For TCP - www.microsoft.com:443 or 10.1.0.4:22 or https://www.github.com",
		"         For ICMP - www.microsoft.com or 10.1.0.4")
	pIf := flagString("if", "", "<string>", "Specified iface name.", "Default: <empty> - All ifaces")

	flag.Parse()

	argIf = *pIf.Str

	if !clientDest.IsZero() || !xClientDest.IsZero() {
		isServer.SetBool(false)
		showUI.SetBool(false)
	}

	if isServer.IsTrue() {
		checkServerModeArgs(bufLenStr, bwRateStr, testTypePtr, title, cport, protocol, ncs, reverse, duration, gap, iterCount, thCount, wc, tos)
	} else if !clientDest.IsZero() || !xClientDest.IsZero() {
		if !clientDest.IsZero() && !xClientDest.IsZero() {
			printUsageError(`Invalid argument, both "-c" and "-x" cannot be specified at the same time.`)
		}
		if showUI.IsTrue() {
			printUsageError(fmt.Sprintf(`"Invalid argument, "-%s" can only be used in server ("-s") mode.`, "ui"))
		}
	}

	// Process common parameters.

	if debug.IsTrue() {
		loggingLevel = LogLevelDebug
	}

	ipVer = setIpVer(*use4.Bool, *use6.Bool)

	if !ip.IsZero() {
		gLocalIP = *ip.Str
		ipAddr := net.ParseIP(gLocalIP)
		if ipAddr == nil {
			printUsageError(fmt.Sprintf("Invalid IP address: <%s> specified.", *ip.Str))
		}
		if !ipVer.IsValid(ipAddr) {
			printUsageError(fmt.Sprintf("Invalid IP address version: <%s> specified.", *ip.Str))
		}
	}
	gPort = uint16(*port.Int)
	gPortStr = fmt.Sprintf("%d", gPort)

	logFileName := *outputFile.Str
	if !*noOutput.Bool {
		if logFileName == defaultLogFileName {
			if *isServer.Bool {
				logFileName = "ethrs.log"
			} else {
				logFileName = "ethrc.log"
			}
		}
		logInit(logFileName)
	}

	var testType TestType
	var destination string
	if *isServer.Bool {
		// Server side parameter processing.
		testType = All
		runServer(serverParam{showUI: *showUI.Bool})
	} else {
		gIsExternalClient = false
		destination = *clientDest.Str
		if *xClientDest.Str != "" {
			gIsExternalClient = true
			destination = *xClientDest.Str
		}
		gNoConnectionStats = *ncs.Bool
		testType = getTestType(*testTypePtr.Str)
		proto := getProtocol(*protocol.Str)

		// Default latency test to 1B if length is not specified
		if bufLenStr.IsZero() {
			bufLenStr.SetStr(getDefaultBufferLenStr(*testTypePtr.Str))
		}
		bufLen := unitToNumber(*bufLenStr.Str)
		if bufLen == 0 {
			printUsageError(fmt.Sprintf("Invalid length specified: %s" + *bufLenStr.Str))
		}

		// Check specific bwRate if any.
		bwRate := uint64(0)
		if *bwRateStr.Str != "" {
			bwRate = unitToNumber(*bwRateStr.Str)
			bwRate /= 8
		}

		//
		// For Pkt/s, we always override the buffer size to be just 1 byte.
		// TODO: Evaluate in future, if we need to support > 1 byte packets for
		//       Pkt/s testing.
		//
		if testType == Pps {
			bufLen = 1
		}

		if *iterCount.Int <= 0 {
			printUsageError(fmt.Sprintf("Invalid iteration count for latency test: %d", *iterCount.Int))
		}

		if *thCount.Int <= 0 {
			*thCount.Int = runtime.NumCPU()
		}

		gClientPort = uint16(*cport.Int)

		testId := TestID{Protocol: proto, Type: testType}
		param := clientParam{
			NumThreads:  thCount.Uint32(),
			BufferSize:  uint32(bufLen),
			RttCount:    iterCount.Uint32(),
			Reverse:     reverse.GetBool(),
			Duration:    duration.GetDuration(),
			Gap:         gap.GetDuration(),
			WarmupCount: wc.Uint32(),
			BwRate:      bwRate,
			ToS:         tos.Uint8(),
		}
		validateClientParams(testId, param)

		runClient(testId, *title.Str, param, destination)
	}
}

func setIpVer(use4, use6 bool) IPVer {
	if use4 && !use6 {
		return iPv4
	} else if use6 && !use4 {
		return iPv6
	}
	return ipAny
}

func getProtocol(protoStr string) (proto Protocol) {
	p := strings.ToUpper(protoStr)
	proto = TCP
	switch p {
	case "TCP":
		proto = TCP
	case "UDP":
		proto = UDP
	case "ICMP":
		proto = ICMP
	default:
		printUsageError(fmt.Sprintf(`Invalid value "%s" specified for parameter "-p".`+
			"\nValid parameters and values are:\n", protoStr))
	}
	return
}

func getTestType(testTypeStr string) (testType TestType) {
	switch testTypeStr {
	case "":
		if gIsExternalClient {
			testType = Ping
		} else {
			testType = Bandwidth
		}
	case "b":
		testType = Bandwidth
	case "c":
		testType = Cps
	case "p":
		testType = Pps
	case "l":
		testType = Latency
	case "pi":
		testType = Ping
	case "tr":
		testType = TraceRoute
	case "mtr":
		testType = MyTraceRoute
	default:
		printUsageError(fmt.Sprintf("Invalid value \"%s\" specified for parameter \"-t\".\n"+
			"Valid parameters and values are:\n", testTypeStr))
	}
	return
}

func getDefaultBufferLenStr(testTypePtr string) string {
	if testTypePtr == "l" {
		return latencyDefaultBufferLenStr
	}
	return defaultBufferLenStr
}

func validateClientParams(testID TestID, clientParam clientParam) {
	if !gIsExternalClient {
		validateClientTest(testID, clientParam)
	} else {
		validateExtModeClientTest(testID)
	}
}

func validateClientTest(testID TestID, clientParam clientParam) {
	testType := testID.Type

	switch protocol := testID.Protocol; protocol {
	case TCP:
		switch testType {
		case Bandwidth, Cps, Latency, Ping, TraceRoute, MyTraceRoute:
		default:
			emitUnsupportedTest(testID)
		}
		if clientParam.Reverse && testType != Bandwidth {
			printReverseModeError()
		}
		if clientParam.BufferSize > 2*GIGA {
			printUsageError(`Maximum allowed value for "-l" for TCP is 2GB.`)
		}
	case UDP:
		switch testType {
		case Bandwidth, Pps:
		default:
			emitUnsupportedTest(testID)
		}
		if testType == Bandwidth {
			if clientParam.BufferSize > (64 * 1024) {
				printUsageError("Maximum supported buffer size for UDP is 64K\n")
			}
		}
		if clientParam.Reverse {
			printReverseModeError()
		}
		if clientParam.BufferSize > 64*KILO {
			printUsageError(`Maximum allowed value for "-l" for TCP is 64KB.`)
		}
	default:
		emitUnsupportedTest(testID)
	}
}

func validateExtModeClientTest(testID TestID) {
	testType := testID.Type
	protocol := testID.Protocol
	switch protocol {
	case TCP:
		switch testType {
		case Ping, Cps, TraceRoute, MyTraceRoute:
		default:
			emitUnsupportedTest(testID)
		}
	case ICMP:
		switch testType {
		case Ping, TraceRoute, MyTraceRoute:
		default:
			emitUnsupportedTest(testID)
		}
	default:
		emitUnsupportedTest(testID)
	}
}

func emitUnsupportedTest(testID TestID) {
	printUsageError(fmt.Sprintf(`Test: "%s" for Protocol: "%s" is not supported.`+"\n", testID.Type, testID.Protocol))
}

func printReverseModeError() {
	printUsageError("Reverse mode (-r) is only supported for TCP Bandwidth tests.")
}

func printUsageError(s string) {
	fmt.Printf("Error: %s\n", s)
	fmt.Printf(`Please use "ethr -h" for complete list of command line arguments.` + "\n")
	os.Exit(1)
}

// ethrUsage prints the command-line usage text
func ethrUsage() {
	fmt.Println("Ethr supports three modes. Usage of each mode is described below:")

	fmt.Println("\n-------------------- Common Parameters -----------------------------------------")
	printFlagUsage("h", "", "Help")
	printFlagUsages("no", "o", "debug", "4", "6", "if")

	fmt.Println("\n-------------------- Mode: Server       ----------------------------------------")
	fmt.Println("In this mode, Ethr runs as a server, allowing multiple clients to run")
	fmt.Println("performance tests against it.")
	printFlagUsages("s", "ip", "port", "ui", "if")

	fmt.Println("\n-------------------- Mode: Client       ----------------------------------------")
	fmt.Println("In this mode, Ethr client can only talk to an Ethr server.")
	printFlagUsages("c", "b", "cport", "d", "g", "i", "ip", "l", "n")
	printFlagUsage("p", "<protocol>", `Protocol ("tcp", "udp", "http", "https", or "icmp")`, "Default: tcp")
	printFlagUsages("port", "r")
	printFlagUsage("t", "<test>", `Test to run ("b", "c", "p", "l", "cl" or "tr")`,
		"b: Bandwidth",
		"c: Connections/s",
		"p: Packets/s",
		"l: Latency, Loss & Jitter",
		"pi: Ping Loss & Latency",
		"tr: TraceRoute",
		"mtr: MyTraceRoute with Loss & Latency",
		"Default: b - Bandwidth measurement.")
	printFlagUsages("tos", "w", "T")

	fmt.Println("\n-------------------- Mode: External         ------------------------------------")
	fmt.Println("In this mode, Ethr talks to a non-Ethr server. This mode supports only a")
	fmt.Println("few types of measurements, such as Ping, Connections/s and TraceRoute.")
	printFlagUsages("x", "cport", "d", "g", "ip", "l")
	printFlagUsage("p", "<protocol>", `"Protocol ("tcp", or "icmp")`, "Default: tcp")
	printFlagUsage("t", "<test>", `Test to run ("c", "cl", or "tr")`,
		"c: Connections/s",
		"pi: Ping Loss & Latency",
		"tr: TraceRoute",
		"mtr: MyTraceRoute with Loss & Latency",
		"Default: pi - Ping Loss & Latency.")
	printFlagUsages("tos", "w", "T")
}

func printFlagUsages(flags ...string) {
	for _, f := range flags {
		printFlagUsage(f)
	}
}

func printFlagUsage(flag string, helptext ...string) {
	var info string

	if len(helptext) == 0 {
		info = flags[flag].info
		helptext = flags[flag].helptext
	} else {
		info = helptext[0]
		helptext = helptext[1:]
	}

	fmt.Printf("\t-%s %s\n", flag, info)
	for _, help := range helptext {
		fmt.Printf("\t\t%s\n", help)
	}
}

type flagUsage struct {
	name            string
	Str             *string
	StrDefault      string
	Int             *int
	IntDefault      int
	Bool            *bool
	BoolDefault     bool
	Duration        *time.Duration
	DurationDefault time.Duration
	info            string
	helptext        []string
}

func (f *flagUsage) IsDefault() bool {
	switch {
	case f.Str != nil:
		return *f.Str == f.StrDefault
	case f.Int != nil:
		return *f.Int == f.IntDefault
	case f.Bool != nil:
		return *f.Bool == f.BoolDefault
	case f.Duration != nil:
		return *f.Duration == f.DurationDefault
	}

	return false
}

func (f *flagUsage) IsZero() bool {
	switch {
	case f.Str != nil:
		return *f.Str == ""
	case f.Int != nil:
		return *f.Int == 0
	case f.Bool != nil:
		return *f.Bool == false
	case f.Duration != nil:
		return *f.Duration == 0
	}

	return false
}

func (f *flagUsage) IsTrue() bool               { return f.Bool != nil && *f.Bool }
func (f *flagUsage) SetBool(b bool)             { *f.Bool = b }
func (f *flagUsage) SetStr(s string)            { *f.Str = s }
func (f *flagUsage) Uint32() uint32             { return uint32(*f.Int) }
func (f *flagUsage) Uint8() uint8               { return uint8(*f.Int) }
func (f *flagUsage) GetBool() bool              { return *f.Bool }
func (f *flagUsage) GetDuration() time.Duration { return *f.Duration }

var flags = make(map[string]*flagUsage)

func flagDuration(name string, value time.Duration, info string, helptext ...string) *flagUsage {
	return addFlags(&flagUsage{name: name, Duration: flag.Duration(name, value, ""), DurationDefault: value, info: info, helptext: helptext})
}

func flagBool(name string, value bool, info string, helptext ...string) *flagUsage {
	return addFlags(&flagUsage{name: name, Bool: flag.Bool(name, value, ""), BoolDefault: value, info: info, helptext: helptext})
}

func flagInt(name string, value int, info string, helptext ...string) *flagUsage {
	return addFlags(&flagUsage{name: name, Int: flag.Int(name, value, ""), IntDefault: value, info: info, helptext: helptext})
}

func flagString(name, value, info string, helptext ...string) *flagUsage {
	return addFlags(&flagUsage{name: name, Str: flag.String(name, value, ""), StrDefault: value, info: info, helptext: helptext})
}

func addFlags(fu *flagUsage) *flagUsage {
	flags[fu.name] = fu
	return fu
}

func checkServerModeArgs(flagArgs ...*flagUsage) {
	for _, arg := range flagArgs {
		if !arg.IsDefault() {
			printUsageError(fmt.Sprintf(`Invalid argument, "-%s" can only be used in client ("-c") mode.`, arg.name))
		}
	}
}
