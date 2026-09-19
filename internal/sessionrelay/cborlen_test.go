package sessionrelay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A length argument of 2^63 or more wrapped negative under int(n) and passed
// the overrun check; make([]byte, n) then panicked. decodeSealed reads the
// map keys (text) before "ct" (bytes), so both readers are exercised.
func TestDecodeSealedHugeLength(t *testing.T) {
	huge := func(major byte, n uint64) []byte {
		b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
	for _, n := range []uint64{1 << 63, 1<<64 - 1, 1<<64 - 2} {
		cases := map[string][]byte{
			"text key":   append([]byte{0xa3}, huge(3, n)...),
			"ct bytes":   append([]byte{0xa3, 0x62, 'c', 't'}, huge(2, n)...),
			"bare bytes": huge(2, n),
		}
		for name, in := range cases {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s n=%d: panic %v", name, n, r)
					}
				}()
				if name == "bare bytes" {
					if _, _, err := readCborBytes(in, 0); err == nil {
						t.Fatalf("%s n=%d: accepted", name, n)
					}
					return
				}
				if _, err := decodeSealed(in); err == nil {
					t.Fatalf("%s n=%d: accepted", name, n)
				}
			}()
		}
	}
}

func TestCborLenBounds(t *testing.T) {
	in := make([]byte, 10)
	if l, err := cborLen(in, 4, 6); err != nil || l != 6 {
		t.Fatalf("exact fit: l=%d err=%v", l, err)
	}
	for _, n := range []uint64{7, 1 << 63, 1<<64 - 1} {
		if _, err := cborLen(in, 4, n); err == nil {
			t.Fatalf("n=%d accepted", n)
		}
	}
	if _, err := cborLen(in, 11, 0); err == nil {
		t.Fatal("end past input accepted")
	}
}

func TestSealedRoundTrip(t *testing.T) {
	env := sealedEnvelope{V: 1, Ctr: 7, Ct: bytes.Repeat([]byte{0xab}, 300)}
	got, err := decodeSealed(encodeSealed(env))
	if err != nil || got.V != 1 || got.Ctr != 7 || !bytes.Equal(got.Ct, env.Ct) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}

// The reporters' input, end to end: a 2^64-1 length in a stream OPEN and in a
// DATA frame. Both are parsed on goroutines the mux starts, where a panic
// ended the manager process. Each must close its stream, and the connection
// must go on serving.
func TestMuxHugeCborLength(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "")
	relayHost := startRelay(t, m, startEchoApp(t))
	c := dialMux(t, relayHost)
	evil := []byte{0xa3, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	c.write(muxTypeOpen, sess.ID, 1, c.openPayload("app.example.org", "/live", evil))
	if typ, _, stream, payload := c.read(); typ != muxTypeClose || stream != 1 {
		t.Fatalf("open: expected CLOSE on stream 1, got type %d stream %d (%q)", typ, stream, payload)
	}

	sealer := newStreamSealer(sess, "/live", 2)
	c.write(muxTypeOpen, sess.ID, 2, c.openPayload("app.example.org", "/live", sealer.seal([]byte("open"), 0)))
	if typ, _, _, payload := c.read(); typ != muxTypeData || string(sealer.unseal(t, payload, 0)) != "ack" {
		t.Fatalf("stream 2 not acked after the bad open: type %d", typ)
	}
	c.write(muxTypeData, sess.ID, 2, evil)
	if typ, _, stream, _ := c.read(); typ != muxTypeClose || stream != 2 {
		t.Fatalf("data: expected CLOSE on stream 2, got type %d stream %d", typ, stream)
	}

	sealer = newStreamSealer(sess, "/live", 3)
	c.write(muxTypeOpen, sess.ID, 3, c.openPayload("app.example.org", "/live", sealer.seal([]byte("open"), 0)))
	if typ, _, _, payload := c.read(); typ != muxTypeData || string(sealer.unseal(t, payload, 0)) != "ack" {
		t.Fatalf("manager stopped serving after the bad frames: type %d", typ)
	}
}
