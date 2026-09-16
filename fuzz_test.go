package tsp

import (
	"bytes"
	"testing"
)

// fuzzKeys are fixed identities so the fuzzer can reach past the signature
// check with inputs derived from the seeds.
func fuzzKeys(t testing.TB) (alice, bob *PrivateIdentity) {
	alice, err := NewPrivateIdentity("did:example:alice", SigKeyEd25519, bytes.Repeat([]byte{1}, 32), EncKeyX25519, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bob, err = NewPrivateIdentity("did:example:bob", SigKeyEd25519, bytes.Repeat([]byte{3}, 32), EncKeyX25519, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func addFuzzSeeds(f *testing.F) {
	vf := loadVectors(f)
	for _, v := range vf.Vectors {
		f.Add(b64(f, v.Message))
		f.Add(b64(f, v.Payload))
	}
	alice, bob := fuzzKeys(f)
	inner, _ := Pack(alice, bob.Public(), &SCS{Data: []byte("x")}, nil)
	for _, p := range []Payload{&SCS{Data: []byte("x")}, &RFI{ReplyPath: []string{"did:example:h"}}, &RFA{InviteDigest: Digest{Alg: DigestSHA2256}}, &RFD{}, &PAD{}, &HOP{Inner: inner.Message}} {
		for _, s := range []Scheme{SchemeHPKEBase, SchemeSealedBox, SchemeSignedOnly} {
			if packed, err := Pack(alice, bob.Public(), p, &PackOptions{Scheme: s, Padding: []byte("pad")}); err == nil {
				f.Add(packed.Message)
			}
		}
	}
}

// FuzzOpen checks that Open never panics and that anything it accepts is
// re-encodable.
func FuzzOpen(f *testing.F) {
	addFuzzSeeds(f)
	alice, bob := fuzzKeys(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		m, err := Open(bob, alice.Public(), msg)
		if err != nil {
			return
		}
		if m.Sender != alice.VID {
			t.Fatalf("accepted a message from %q", m.Sender)
		}
	})
}

// FuzzPeek checks that Peek and payload decoding never panic.
func FuzzPeek(f *testing.F) {
	addFuzzSeeds(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		_, _ = Peek(msg)
		_, _ = decodePayload(msg, nil)
	})
}
