package cesr

import (
	"bytes"
	"errors"
	"testing"
)

func text(t *testing.T, b []byte) string {
	t.Helper()
	s, err := ToText(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCodesRenderAsSpecified(t *testing.T) {
	b, _ := AppendCount(nil, CodeE, 69)
	if got := text(t, b); got != "-EBF" {
		t.Errorf("short count: %s", got)
	}
	b, _ = AppendCount(nil, CodeE, 5000)
	if got := text(t, b); got != "--EAABOI" {
		t.Errorf("long count: %s", got)
	}
	b, _ = AppendVersion(nil, 0, 2)
	if got := text(t, b); got != "YTSP-AAC" {
		t.Errorf("version: %s", got)
	}
	b, _ = AppendVarData(nil, CodeB, nil)
	if got := text(t, b); got != "4BAA" {
		t.Errorf("NULL VID: %s", got)
	}
	b, _ = AppendVarData(nil, CodeB, []byte("hello world"))
	if got := text(t, b); got != "5BAEAGhlbGxvIHdvcmxk" {
		t.Errorf("bytes: %s", got)
	}
	b, _ = AppendFixed(nil, uint32(CodeA), bytes.Repeat([]byte{0x11}, 16))
	if got := text(t, b); got[:2] != "0A" || len(got) != 24 {
		t.Errorf("nonce: %s", got)
	}
	b, _ = AppendFixed(nil, uint32(CodeI), make([]byte, 32))
	if got := text(t, b); got[:1] != "I" || len(got) != 44 {
		t.Errorf("digest: %s", got)
	}
	b, _ = AppendFixed(nil, CodeMLDSA65, make([]byte, 3309))
	if got := text(t, b); got[:4] != "1AAQ" || len(got) != 4416 {
		t.Errorf("ML-DSA-65: %s", got[:4])
	}
	b, _ = AppendIndexedEd25519(nil, 0, make([]byte, 64))
	if got := text(t, b); got[:2] != "BA" || len(got) != 88 {
		t.Errorf("Ed25519: %s", got[:2])
	}
	for s, want := range map[string][3]byte{"XSCS": {0x5d, 0x20, 0x92}, "YTSP": {0x61, 0x34, 0x8f}} {
		if Tag(s) != want {
			t.Errorf("Tag(%s) = %x", s, Tag(s))
		}
	}
}

func TestCountRoundTripAndCanonical(t *testing.T) {
	for _, n := range []int{0, 1, 4095, 4096, 1 << 24, MaxLongCount} {
		b, err := AppendCount(nil, CodeZ, n)
		if err != nil {
			t.Fatal(err)
		}
		got, used, err := ReadCount(b, CodeZ)
		if err != nil || got != n || used != len(b) {
			t.Fatalf("count %d: got %d, %d, %v", n, got, used, err)
		}
	}
	if _, err := AppendCount(nil, CodeZ, MaxLongCount+1); err == nil {
		t.Fatal("encoded an oversized count")
	}
	// A long form carrying a short count is non-canonical.
	long := []byte{0xfb, 0xe6, 0x40, 0, 0, 5}
	if _, _, err := ReadCount(long, CodeZ); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("long form of a short count: %v", err)
	}
	if _, _, err := ReadCount([]byte{0xf8, 0x40}, CodeE); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: %v", err)
	}
	if _, _, err := ReadCount([]byte{0xf8, 0x40, 0x13}, CodeZ); !errors.Is(err, ErrUnexpectedCode) {
		t.Fatalf("wrong code: %v", err)
	}
}

func TestVarDataRoundTripAndCanonical(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 3*4095 - 1, 3 * 4095, 3*4095 + 1, 3*4096 + 2} {
		data := bytes.Repeat([]byte{0xAB}, n)
		b, err := AppendVarData(nil, CodeF, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != VarDataSize(n) || len(b)%3 != 0 {
			t.Fatalf("size %d: encoded %d bytes, VarDataSize %d", n, len(b), VarDataSize(n))
		}
		got, used, err := ReadVarData(b, CodeF)
		if err != nil || !bytes.Equal(got, data) || used != len(b) {
			t.Fatalf("size %d: %v", n, err)
		}
		if !PeekVarDataCode(b, CodeF) || PeekVarDataCode(b, CodeC) {
			t.Fatalf("size %d: PeekVarDataCode", n)
		}
	}
	// Non-zero lead byte.
	b, _ := AppendVarData(nil, CodeB, []byte("did:web:bob.example")) // 2 lead bytes
	b[3] = 1
	if _, _, err := ReadVarData(b, CodeB); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("lead byte: %v", err)
	}
	// Lead bytes on an empty primitive.
	if _, _, err := ReadVarData([]byte{0xe4, 0x10, 0x00}, CodeB); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("5BAA: %v", err)
	}
	// Long form for a short size.
	long := []byte{0xec, 0x00, 0x01, 0x00, 0x00, 0x01, 0x61, 0x62, 0x63}
	if _, _, err := ReadVarData(long, CodeB); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("long form: %v", err)
	}
	// Truncated.
	b, _ = AppendVarData(nil, CodeB, []byte("abcdef"))
	if _, _, err := ReadVarData(b[:len(b)-1], CodeB); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: %v", err)
	}
}

func TestFixedAndSignature(t *testing.T) {
	d := bytes.Repeat([]byte{9}, 32)
	b, _ := AppendFixed(nil, uint32(CodeI), d)
	if got, n, err := ReadFixed(b, uint32(CodeI), 32); err != nil || !bytes.Equal(got, d) || n != 33 {
		t.Fatal(err)
	}
	if _, _, err := ReadFixed(b, uint32(CodeF), 32); err == nil {
		t.Fatal("read an I digest as F")
	}
	b[0] |= 1 // pad bit
	if _, _, err := ReadFixed(b, uint32(CodeI), 32); err == nil {
		t.Fatal("accepted non-zero pad bits")
	}

	sig := bytes.Repeat([]byte{5}, 64)
	b, _ = AppendIndexedEd25519(nil, 3, sig)
	idx, got, n, err := ReadIndexedEd25519(b)
	if err != nil || idx != 3 || !bytes.Equal(got, sig) || n != 66 {
		t.Fatal(err)
	}
	b[1] |= 1
	if _, _, _, err := ReadIndexedEd25519(b); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("pad bits: %v", err)
	}
}

func TestVersionAndText(t *testing.T) {
	b, _ := AppendVersion(nil, 0, 2)
	major, minor, n, err := ReadVersion(b)
	if err != nil || major != 0 || minor != 2 || n != 6 {
		t.Fatal(err)
	}
	if _, _, _, err := ReadVersion([]byte("not-tsp")); err == nil {
		t.Fatal("read a version from junk")
	}
	back, err := FromText("YTSP-AAC")
	if err != nil || !bytes.Equal(back, b) {
		t.Fatal(err)
	}
	if _, err := FromText("YTS"); err == nil {
		t.Fatal("accepted a partial quadlet")
	}
	if _, err := ToText([]byte{1}); err == nil {
		t.Fatal("accepted a partial triplet")
	}
}
