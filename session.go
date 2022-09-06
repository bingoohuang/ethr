// -----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
// -----------------------------------------------------------------------------
package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"encoding/gob"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type TestType uint32

const (
	All TestType = iota
	Bandwidth
	Cps
	Pps
	Latency
	Ping
	TraceRoute
	MyTraceRoute
)

type Protocol uint32

const (
	TCP Protocol = iota
	UDP
	ICMP
)

const (
	ICMPv4 = 1  // ICMP for IPv4
	ICMPv6 = 58 // ICMP for IPv6
)

type TestID struct {
	Protocol Protocol
	Type     TestType
}

type MsgType uint32

const (
	Inv MsgType = iota
	Syn
	Ack
)

type MsgVer uint32

type Msg struct {
	Version MsgVer
	Type    MsgType
	Syn     *MsgSyn
	Ack     *MsgAck
}

type MsgSyn struct {
	TestID      TestID
	ClientParam clientParam
}

type MsgAck struct{}

type testResult struct {
	bw      uint64
	cps     uint64
	pps     uint64
	latency uint64
}

type test struct {
	isActive    bool
	isDormant   bool
	session     *session
	remoteAddr  string
	remoteIP    string
	remotePort  string
	dialAddr    string
	refCount    int32
	testID      TestID
	clientParam clientParam
	testResult  testResult
	done        chan struct{}
	connList    *list.List
	lastAccess  time.Time
}

type IPVer uint32

const (
	ipAny IPVer = iota
	iPv4
	iPv6
)

func (v IPVer) IsValid(ipAddr net.IP) bool {
	return ipVer == ipAny || v == iPv4 && ipAddr.To4() != nil || v == iPv6 && ipAddr.To16() != nil
}

type clientParam struct {
	NumThreads  uint32
	BufferSize  uint32
	RttCount    uint32
	Reverse     bool
	Duration    time.Duration
	Gap         time.Duration
	WarmupCount uint32
	BwRate      uint64
	ToS         uint8
}

type serverParam struct {
	showUI bool
}

var (
	ipVer             = ipAny
	gIsExternalClient bool
)

type conn struct {
	bw      uint64
	pps     uint64
	test    *test
	conn    net.Conn
	elem    *list.Element
	fd      uintptr
	retrans uint64
}

type session struct {
	remoteIP  string
	testCount uint32
	tests     map[TestID]*test
}

var (
	gSessions    = make(map[string]*session)
	gSessionKeys []string
	gSessionLock sync.RWMutex
)

func deleteKey(key string) {
	i := 0
	for _, x := range gSessionKeys {
		if x != key {
			gSessionKeys[i] = x
			i++
		}
	}
	gSessionKeys = gSessionKeys[:i]
}

func newTest(remoteIP string, testID TestID, clientParam clientParam) (*test, error) {
	gSessionLock.Lock()
	defer gSessionLock.Unlock()
	return newTestInternal(remoteIP, testID, clientParam)
}

func newTestInternal(remoteIP string, testID TestID, clientParam clientParam) (*test, error) {
	s, found := gSessions[remoteIP]
	if !found {
		s = &session{}
		s.remoteIP = remoteIP
		s.tests = make(map[TestID]*test)
		gSessions[remoteIP] = s
		gSessionKeys = append(gSessionKeys, remoteIP)
	}

	t, found := s.tests[testID]
	if found {
		return t, os.ErrExist
	}
	s.testCount++
	t = &test{}
	t.session = s
	t.refCount = 0
	t.testID = testID
	t.clientParam = clientParam
	t.done = make(chan struct{})
	t.connList = list.New()
	t.lastAccess = time.Now()
	t.isDormant = true
	s.tests[testID] = t

	return t, nil
}

func (t *test) deleteTestInternal() {
	sess := t.session

	// TODO fix this, we need to decide where to close this, inside this
	// function or by the caller. The reason we may need it to be done by
	// the caller is, because done is used for test done notification and
	// there may be some time after done that consumers are still accessing it
	//
	// Since we have not added any refCounting on test object, we are doing
	// hacky timeout based solution by closing "done" outside and sleeping
	// for sufficient time. ugh!
	//
	// close(test.done)
	// test.ctrlConn.Close()
	// test.session = nil
	// test.connList = test.connList.Init()
	delete(sess.tests, t.testID)
	sess.testCount--

	if sess.testCount == 0 {
		deleteKey(sess.remoteIP)
		delete(gSessions, sess.remoteIP)
	}
}

func getTestInternal(remoteIP string, proto Protocol, testType TestType) (test *test) {
	session, found := gSessions[remoteIP]
	if !found {
		return
	}
	test, _ = session.tests[TestID{proto, testType}]
	return
}

func createOrGetTest(remoteIP string, proto Protocol, testType TestType) (test *test, isNew bool) {
	gSessionLock.Lock()
	defer gSessionLock.Unlock()
	test = getTestInternal(remoteIP, proto, testType)
	if isNew = test == nil; isNew {
		testID := TestID{proto, testType}
		test, _ = newTestInternal(remoteIP, testID, clientParam{})
		test.isActive = true
	}
	atomic.AddInt32(&test.refCount, 1)
	return
}

func (t *test) safeDeleteTest() {
	gSessionLock.Lock()
	defer gSessionLock.Unlock()
	if atomic.AddInt32(&t.refCount, -1) == 0 {
		t.deleteTestInternal()
	}
}

func (t *test) newConn(c net.Conn) (ec *conn) {
	gSessionLock.Lock()
	defer gSessionLock.Unlock()
	ec = &conn{}
	ec.test = t
	ec.conn = c
	ec.fd = getFd(c)
	ec.elem = t.connList.PushBack(ec)
	return
}

func (t *test) delConn(c net.Conn) {
	for e := t.connList.Front(); e != nil; e = e.Next() {
		ec := e.Value.(*conn)
		if ec.conn == c {
			t.connList.Remove(e)
			break
		}
	}
}

func (t *test) connListDo(f func(*conn)) {
	gSessionLock.RLock()
	defer gSessionLock.RUnlock()
	for e := t.connList.Front(); e != nil; e = e.Next() {
		ec := e.Value.(*conn)
		f(ec)
	}
}

func createSynMsg(testID TestID, clientParam clientParam) (msg *Msg) {
	msg = &Msg{Version: 0, Type: Syn}
	msg.Syn = &MsgSyn{}
	msg.Syn.TestID = testID
	msg.Syn.ClientParam = clientParam
	return
}

func createAckMsg() *Msg {
	return &Msg{Version: 0, Type: Ack, Ack: &MsgAck{}}
}

func recvSessionMsg(conn net.Conn) (msg *Msg) {
	msg = &Msg{}
	msg.Type = Inv

	msgBytes := make([]byte, 4)
	if _, err := io.ReadFull(conn, msgBytes); err != nil {
		ui.printDbg("Error receiving message on control channel. Error: %v", err)
		return
	}
	msgSize := binary.BigEndian.Uint32(msgBytes[0:])
	// TODO: Assuming max ethr message size as 16K sent over gob.
	if msgSize > 16384 {
		return
	}
	msgBytes = make([]byte, msgSize)
	if _, err := io.ReadFull(conn, msgBytes); err != nil {
		ui.printDbg("Error receiving message on control channel. Error: %v", err)
		return
	}
	msg = decodeMsg(msgBytes)
	return
}

func (m *Msg) send(conn net.Conn) (err error) {
	msgBytes, err := m.encodeMsg()
	if err != nil {
		ui.printDbg("Error sending message on control channel. Message: %v, Error: %v", m, err)
		return
	}
	tempBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tempBuf[0:], uint32(len(msgBytes)))
	if _, err = conn.Write(tempBuf); err != nil {
		ui.printDbg("Error write message on control channel. Message: %v, Error: %v", m, err)
	}
	if _, err = conn.Write(msgBytes); err != nil {
		ui.printDbg("Error write message on control channel. Message: %v, Error: %v", m, err)
	}
	return err
}

func decodeMsg(msgBytes []byte) (msg *Msg) {
	msg = &Msg{}
	buffer := bytes.NewBuffer(msgBytes)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(msg); err != nil {
		ui.printDbg("Failed to decode message using Gob: %v", err)
		msg.Type = Inv
	}
	return
}

func (m *Msg) encodeMsg() ([]byte, error) {
	var writeBuffer bytes.Buffer
	encoder := gob.NewEncoder(&writeBuffer)
	if err := encoder.Encode(m); err != nil {
		ui.printDbg("Failed to encode message using Gob: %v", err)
		return nil, err
	}
	return writeBuffer.Bytes(), nil
}
