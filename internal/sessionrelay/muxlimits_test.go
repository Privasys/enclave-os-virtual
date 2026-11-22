// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A frame header declaring a large payload costs memory only for the bytes
// that actually arrive.
func TestReadMuxFrameGrowsWithArrivedBytes(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write([]byte{muxTypeData, 1, 'x'})
	var rest [12]byte
	binary.BigEndian.PutUint64(rest[:8], 1)
	binary.BigEndian.PutUint32(rest[8:], muxMaxFrame)
	hdr.Write(rest[:])
	hdr.Write(make([]byte, 100)) // then the peer stops sending

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, _, _, err := readMuxFrame(bufio.NewReader(&hdr))
	runtime.ReadMemStats(&after)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes for a 100-byte partial frame", grew)
	}
}

func TestReadMuxFrameFullPayload(t *testing.T) {
	want := bytes.Repeat([]byte("abcdefgh"), 3*muxReadChunk/8+5)
	var b bytes.Buffer
	b.Write([]byte{muxTypeData, 0})
	var rest [12]byte
	binary.BigEndian.PutUint64(rest[:8], 9)
	binary.BigEndian.PutUint32(rest[8:], uint32(len(want)))
	b.Write(rest[:])
	b.Write(want)
	typ, _, stream, got, err := readMuxFrame(bufio.NewReader(&b))
	if err != nil || typ != muxTypeData || stream != 9 || !bytes.Equal(got, want) {
		t.Fatalf("typ=%d stream=%d len=%d err=%v", typ, stream, len(got), err)
	}
}

func TestMuxConnectionLimit(t *testing.T) {
	m := NewManager()
	m.maxMuxConns = 1
	relayHost := startRelay(t, m, startEchoApp(t))
	_ = dialMux(t, relayHost) // holds the only slot

	conn, err := net.DialTimeout("tcp", relayHost, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: relay\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", muxPath, muxProtocol)
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, "503") {
		t.Fatalf("second mux upgrade: %q err=%v, want 503", status, err)
	}
}

func TestMuxStreamQueueByteBudget(t *testing.T) {
	st := &muxStream{}
	big := make([]byte, muxStreamQueueBytes+1)
	if !st.enqueue(big) {
		t.Fatal("a frame onto an empty queue must be admitted")
	}
	if st.enqueue([]byte{1}) {
		t.Fatal("queue over budget must refuse")
	}
	st.queued.Add(-int64(len(big)))
	half := make([]byte, muxStreamQueueBytes/2)
	if !st.enqueue(half) || !st.enqueue(half) {
		t.Fatal("frames within budget must be admitted")
	}
	if st.enqueue([]byte{1}) {
		t.Fatal("a full budget must refuse")
	}
}
