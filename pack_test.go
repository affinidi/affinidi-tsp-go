package tsp

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/affinidi/affinidi-tsp-go/cesr"
	tspcrypto "github.com/affinidi/affinidi-tsp-go/crypto"
)

func genID(t testing.TB, vid string, sig SigKeyType, enc EncKeyType) *PrivateIdentity {
	t.Helper()
	id, err := GenerateIdentity(vid, sig, enc, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func classicPair(t testing.TB) (*PrivateIdentity, *PrivateIdentity) {
	return genID(t, "did:example:alice", SigKeyEd25519, EncKeyX25519),
		genID(t, "did:example:bob", SigKeyEd25519, EncKeyX25519)
}

func expectKind(t *testing.T, err error, kind ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %v error, got nil", kind)
	}
	if KindOf(err) != kind {
		t.Fatalf("expected a %v error, got %v", kind, err)
	}
}

func samplePayloads(t *testing.T, inner []byte) []Payload {
	d := Digest{Alg: DigestSHA2256, Value: [32]byte{1, 2, 3}}
	return []Payload{
		&SCS{Data: []byte("hello world")},
		&SCS{Data: []byte{}},
		&CTL{Data: []byte(`{"op":"ping"}`)},
		&PAD{Nonce: bytes.Repeat([]byte{7}, 16)},
		&PAD{},
		&RFI{},
		&RFI{Nonce: bytes.Repeat([]byte{1}, 16), ReplyPath: []string{"did:example:hop1", "did:example:exit"}},
		&RFA{InviteDigest: d},
		&RFD{Digest: d},
		&RFD{Digest: Digest{Alg: DigestBlake2b256, Value: [32]byte{9}}},
		&HOP{Inner: inner},
		&HOP{Hops: []string{"did:example:p", "did:example:q"}, Inner: inner},
	}
}

func TestRoundTripAllSchemesAndPayloads(t *testing.T) {
	alice, bob := classicPair(t)
	pqAlice := genID(t, "did:example:pq-alice", SigKeyMLDSA65, EncKeyMLKEM768X25519)
	pqBob := genID(t, "did:example:pq-bob", SigKeyMLDSA65, EncKeyMLKEM768X25519)
	innerMsg, err := Pack(alice, bob.Public(), &SCS{Data: []byte("inner")}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		scheme           Scheme
		sender, receiver *PrivateIdentity
	}{
		{SchemeHPKEBase, alice, bob},
		{SchemeSealedBox, alice, bob},
		{SchemeSignedOnly, alice, bob},
		{SchemeHPKEPQ, pqAlice, pqBob},
		{SchemeSignedOnly, pqAlice, pqBob},
		{SchemeAuto, alice, bob},
	}
	for _, c := range cases {
		for i, p := range samplePayloads(t, innerMsg.Message) {
			for _, sf := range []SenderField{SenderFieldDefault, SenderFieldNull, SenderFieldPresent} {
				for _, padding := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0}, 100)} {
					name := fmt.Sprintf("%v/%d-%T/sender%d/pad%d", c.scheme, i, p, sf, len(padding))
					t.Run(name, func(t *testing.T) {
						opts := &PackOptions{Scheme: c.scheme, PayloadSender: sf, Padding: padding}
						packed, err := Pack(c.sender, c.receiver.Public(), p, opts)
						if _, hop := p.(*HOP); hop && c.scheme == SchemeSignedOnly {
							expectKind(t, err, KindInvalidInput)
							return
						}
						if sf == SenderFieldNull && c.scheme != SchemeSignedOnly {
							// TSP 1.0: a confidential payload must name its sender.
							expectKind(t, err, KindInvalidInput)
							return
						}
						if err != nil {
							t.Fatalf("Pack: %v", err)
						}
						env, err := Peek(packed.Message)
						if err != nil {
							t.Fatalf("Peek: %v", err)
						}
						if env.Confidential != (c.scheme != SchemeSignedOnly) || env.SealedBox != (c.scheme == SchemeSealedBox) {
							t.Fatalf("Peek: %+v", env)
						}
						m, err := Open(c.receiver, c.sender.Public(), packed.Message)
						if err != nil {
							t.Fatalf("Open: %v", err)
						}
						wantScheme := c.scheme
						if wantScheme == SchemeAuto {
							wantScheme = SchemeHPKEBase
						}
						if m.Scheme != wantScheme || m.Sender != c.sender.VID || m.Receiver != c.receiver.VID {
							t.Fatalf("envelope: %+v", m)
						}
						wantSender := c.sender.VID
						if sf == SenderFieldNull {
							wantSender = ""
						}
						if m.PayloadSender != wantSender {
							t.Fatalf("payload sender %q, want %q", m.PayloadSender, wantSender)
						}
						if !bytes.Equal(m.Padding, padding) {
							t.Fatalf("padding %x, want %x", m.Padding, padding)
						}
						checkRoundTripPayload(t, p, m.Payload, packed)
					})
				}
			}
		}
	}
}

func checkRoundTripPayload(t *testing.T, in, out Payload, packed *Packed) {
	t.Helper()
	switch in := in.(type) {
	case *SCS:
		o := out.(*SCS)
		if !bytes.Equal(o.Data, in.Data) || o.Data == nil {
			t.Fatalf("data %q, want %q", o.Data, in.Data)
		}
	case *CTL:
		if !bytes.Equal(out.(*CTL).Data, in.Data) {
			t.Fatal("control data")
		}
	case *PAD:
		o := out.(*PAD)
		if len(o.Nonce) != NonceSize || (in.Nonce != nil && !bytes.Equal(o.Nonce, in.Nonce)) {
			t.Fatal("padding nonce")
		}
	case *RFI:
		o := out.(*RFI)
		if packed.Digest == nil || !o.Digest.Equal(*packed.Digest) || len(o.Nonce) != NonceSize {
			t.Fatal("invite digest")
		}
		if len(o.ReplyPath) != len(in.ReplyPath) {
			t.Fatal("reply path")
		}
	case *RFA:
		o := out.(*RFA)
		if !o.InviteDigest.Equal(in.InviteDigest) || packed.Digest == nil || !o.ReplyDigest.Equal(*packed.Digest) {
			t.Fatal("accept digests")
		}
	case *RFD:
		if !out.(*RFD).Digest.Equal(in.Digest) || packed.Digest != nil {
			t.Fatal("cancel digest")
		}
	case *HOP:
		o := out.(*HOP)
		if !bytes.Equal(o.Inner, in.Inner) || len(o.Hops) != len(in.Hops) {
			t.Fatal("hop")
		}
	}
}

func TestLongFormsAcrossTheCountBoundary(t *testing.T) {
	alice, bob := classicPair(t)
	// 3*4095 bytes is the largest short payload; go past it in every field.
	for _, n := range []int{3*4095 - 40, 3*4095 - 20, 3 * 4095, 3*4095 + 1, 20000, 1 << 20} {
		for _, scheme := range []Scheme{SchemeHPKEBase, SchemeSealedBox, SchemeSignedOnly} {
			data := bytes.Repeat([]byte{0x5a}, n)
			packed, err := Pack(alice, bob.Public(), &SCS{Data: data}, &PackOptions{Scheme: scheme, Padding: make([]byte, n%7)})
			if err != nil {
				t.Fatalf("%d/%v: %v", n, scheme, err)
			}
			m, err := Open(bob, alice.Public(), packed.Message)
			if err != nil {
				t.Fatalf("%d/%v: %v", n, scheme, err)
			}
			if !bytes.Equal(m.Payload.(*SCS).Data, data) {
				t.Fatalf("%d/%v: data mismatch", n, scheme)
			}
		}
	}
	// A long VID.
	long := "did:example:" + string(bytes.Repeat([]byte("a"), 13000))
	carol := genID(t, long, SigKeyEd25519, EncKeyX25519)
	packed, err := Pack(carol, bob.Public(), &RFI{ReplyPath: []string{long}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Open(bob, carol.Public(), packed.Message)
	if err != nil {
		t.Fatal(err)
	}
	if m.Payload.(*RFI).ReplyPath[0] != long {
		t.Fatal("long VID in reply path")
	}
}

func TestReferral(t *testing.T) {
	alice, bob := classicPair(t)
	newVID := genID(t, "did:example:alice-2", SigKeyEd25519, EncKeyX25519)
	pqVID := genID(t, "did:example:alice-pq", SigKeyMLDSA65, EncKeyMLKEM768X25519)

	for _, introduced := range []*PrivateIdentity{newVID, pqVID} {
		rfi := &RFI{ReplyPath: []string{"did:example:hop"}, Referral: &Referral{VID: introduced.VID}}
		packed, err := Pack(alice, bob.Public(), rfi, &PackOptions{ReferralSigner: introduced, PayloadSender: SenderFieldPresent})
		if err != nil {
			t.Fatal(err)
		}
		m, err := Open(bob, alice.Public(), packed.Message)
		if err != nil {
			t.Fatal(err)
		}
		got := m.Payload.(*RFI)
		if got.Referral == nil || got.Referral.VID != introduced.VID {
			t.Fatal("referral lost")
		}
		if err := VerifyReferral(m, introduced.Public()); err != nil {
			t.Fatalf("VerifyReferral: %v", err)
		}
		expectKind(t, VerifyReferral(m, alice.Public()), KindSender)
		other := *introduced.Public()
		other.SigningKey = alice.SigningKey
		if introduced.SigKeyType == SigKeyEd25519 {
			expectKind(t, VerifyReferral(m, &other), KindSignature)
		}

		// A caller-supplied signature is carried verbatim, unverified.
		sig := bytes.Repeat([]byte{3}, len(got.Referral.Signature))
		packed, err = Pack(alice, bob.Public(), &RFI{Referral: &Referral{VID: introduced.VID, Signature: sig}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		m, err = Open(bob, alice.Public(), packed.Message)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m.Payload.(*RFI).Referral.Signature, sig) {
			t.Fatal("verbatim referral signature")
		}
		expectKind(t, VerifyReferral(m, introduced.Public()), KindSignature)
	}

	_, err := Pack(alice, bob.Public(), &RFI{Referral: &Referral{VID: newVID.VID}}, nil)
	expectKind(t, err, KindInvalidInput)
}

func TestDeterministicPacking(t *testing.T) {
	alice, bob := classicPair(t)
	ikm := bytes.Repeat([]byte{4}, 32)
	nonce := bytes.Repeat([]byte{5}, 16)
	for _, scheme := range []Scheme{SchemeHPKEBase, SchemeSealedBox} {
		a, err := Pack(alice, bob.Public(), &RFI{Nonce: nonce}, &PackOptions{Scheme: scheme, Ephemeral: ikm})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := Pack(alice, bob.Public(), &RFI{Nonce: nonce}, &PackOptions{Scheme: scheme, Ephemeral: ikm})
		if !bytes.Equal(a.Message, b.Message) {
			t.Fatalf("%v: not deterministic", scheme)
		}
	}
	pqA := genID(t, "did:example:a", SigKeyMLDSA65, EncKeyMLKEM768X25519)
	_, err := Pack(pqA, pqA.Public(), &SCS{}, &PackOptions{Ephemeral: ikm})
	expectKind(t, err, KindUnsupported)
}

func TestOpenRejections(t *testing.T) {
	alice, bob := classicPair(t)
	carol := genID(t, "did:example:carol", SigKeyEd25519, EncKeyX25519)

	packed, err := Pack(alice, bob.Public(), &RFI{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := packed.Message

	t.Run("wrong receiver", func(t *testing.T) {
		_, err := Open(carol, alice.Public(), msg)
		expectKind(t, err, KindReceiver)
	})
	t.Run("wrong sender", func(t *testing.T) {
		_, err := Open(bob, carol.Public(), msg)
		expectKind(t, err, KindSender)
	})
	t.Run("wrong sender key", func(t *testing.T) {
		impostor := *alice.Public()
		impostor.SigningKey = carol.SigningKey
		_, err := Open(bob, &impostor, msg)
		expectKind(t, err, KindSignature)
	})
	t.Run("wrong decryption key", func(t *testing.T) {
		wrong := *bob
		wrong.DecryptionPrivateKey = carol.DecryptionPrivateKey
		wrong.EncryptionKey = carol.EncryptionKey
		_, err := Open(&wrong, alice.Public(), msg)
		expectKind(t, err, KindDecrypt)
	})
	t.Run("signature type mismatch", func(t *testing.T) {
		pq := genID(t, alice.VID, SigKeyMLDSA65, EncKeyX25519)
		_, err := Open(bob, pq.Public(), msg)
		expectKind(t, err, KindSignature)
	})
	t.Run("trailing bytes", func(t *testing.T) {
		_, err := Open(bob, alice.Public(), append(append([]byte(nil), msg...), 0, 0, 0))
		expectKind(t, err, KindMalformed)
		_, err = Peek(append(append([]byte(nil), msg...), 0, 0, 0))
		expectKind(t, err, KindMalformed)
	})
	t.Run("truncated", func(t *testing.T) {
		for n := 0; n < len(msg); n++ {
			if _, err := Open(bob, alice.Public(), msg[:n]); err == nil {
				t.Fatalf("accepted a message truncated to %d bytes", n)
			}
		}
	})
	t.Run("every byte flip", func(t *testing.T) {
		for i := range msg {
			for _, bit := range []byte{0x01, 0x80} {
				m := append([]byte(nil), msg...)
				m[i] ^= bit
				if _, err := Open(bob, alice.Public(), m); err == nil {
					t.Fatalf("accepted a message with byte %d flipped by %#x", i, bit)
				}
			}
		}
	})
	t.Run("unknown major version", func(t *testing.T) {
		// Rev 3 (YTSP-AAC) is refused: the version field follows the 3-byte -E
		// code, and is 6 bytes including the YTSP tag.
		m := append([]byte(nil), msg...)
		rev3, _ := cesr.AppendVersion(nil, 0, 2)
		copy(m[3:3+len(rev3)], rev3)
		_, err := Peek(m)
		expectKind(t, err, KindVersion)
		_, err = Open(bob, alice.Public(), m)
		expectKind(t, err, KindVersion)
	})
	t.Run("minor version is carried", func(t *testing.T) {
		signed, err := Pack(alice, bob.Public(), &SCS{Data: []byte("x")}, &PackOptions{Scheme: SchemeSignedOnly})
		if err != nil {
			t.Fatal(err)
		}
		m := resign(t, alice, signed.Message, func(b []byte) []byte { b[8] = 0x40; return b }) // YTSP-ABA
		got, err := Open(bob, alice.Public(), m)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != (Version{1, 64}) {
			t.Fatalf("version %v", got.Version)
		}
	})
}

// resign applies edit to the signable part of msg and signs it again with
// signer's key, producing a message whose signature verifies.
func resign(t *testing.T, signer *PrivateIdentity, msg []byte, edit func([]byte) []byte) []byte {
	t.Helper()
	pm, err := parseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	signed := edit(append([]byte(nil), pm.signed...))
	sig, err := sign(signer, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := appendSignatureAttachment(signed, sig)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// buildSignedOnly assembles a signed-only message around an arbitrary payload
// frame, so tests can exercise payload checks behind a valid signature.
func buildSignedOnly(t *testing.T, sender *PrivateIdentity, receiverVID string, frame []byte) []byte {
	t.Helper()
	env, _ := cesr.AppendVersion(nil, CurrentVersion.Major, CurrentVersion.Minor)
	env, _ = appendVID(env, sender.VID)
	env, _ = appendVID(env, receiverVID)
	msg, _ := cesr.AppendCount(nil, cesr.CodeE, (len(env)+len(frame))/3)
	msg = append(append(msg, env...), frame...)
	sig, err := sign(sender, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = appendSignatureAttachment(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func envFieldsFor(sender, receiver string) []byte {
	env, _ := cesr.AppendVersion(nil, CurrentVersion.Major, CurrentVersion.Minor)
	env, _ = appendVID(env, sender)
	env, _ = appendVID(env, receiver)
	return env
}

func TestPayloadChecksBehindAValidSignature(t *testing.T) {
	alice, bob := classicPair(t)
	nonceGen := func() ([]byte, error) { return make([]byte, 16), nil }

	t.Run("ESSR sender mismatch", func(t *testing.T) {
		sf, _ := appendVID(nil, "did:example:mallory")
		frame, _, err := encodePayload(&SCS{Data: []byte("x")}, &frameInput{
			envFields: envFieldsFor(alice.VID, bob.VID), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(bob, alice.Public(), buildSignedOnly(t, alice, bob.VID, frame))
		expectKind(t, err, KindSender)
	})

	t.Run("invite digest bound to envelope", func(t *testing.T) {
		// A digest computed for a different receiver does not verify.
		sf, _ := appendVID(nil, "")
		frame, _, err := encodePayload(&RFI{}, &frameInput{
			envFields: envFieldsFor(alice.VID, "did:example:carol"), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(bob, alice.Public(), buildSignedOnly(t, alice, bob.VID, frame))
		expectKind(t, err, KindDigest)
	})

	t.Run("accept digest tampered", func(t *testing.T) {
		sf, _ := appendVID(nil, "")
		frame, _, err := encodePayload(&RFA{InviteDigest: Digest{Alg: DigestSHA2256}}, &frameInput{
			envFields: envFieldsFor(alice.VID, bob.VID), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen,
		})
		if err != nil {
			t.Fatal(err)
		}
		frame[len(frame)-4] ^= 1 // last byte of the reply digest (before the 3-byte empty padding)
		_, err = Open(bob, alice.Public(), buildSignedOnly(t, alice, bob.VID, frame))
		expectKind(t, err, KindDigest)
	})

	t.Run("padding does not change the digest", func(t *testing.T) {
		sf, _ := appendVID(nil, "")
		in := &frameInput{envFields: envFieldsFor(alice.VID, bob.VID), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen}
		_, d1, _ := encodePayload(&RFI{}, in)
		in.padding = []byte("some padding")
		_, d2, _ := encodePayload(&RFI{}, in)
		if !d1.Equal(*d2) {
			t.Fatal("padding changed the SAID")
		}
	})

	t.Run("sealed box requires ESSR sender", func(t *testing.T) {
		sf, _ := appendVID(nil, "")
		env := envFieldsFor(alice.VID, bob.VID)
		frame, _, err := encodePayload(&SCS{Data: []byte("x")}, &frameInput{envFields: env, senderField: sf, digestAlg: DigestBlake2b256, nonce: nonceGen})
		if err != nil {
			t.Fatal(err)
		}
		ct, err := tspcrypto.SealedBoxSeal(bob.EncryptionKey, frame, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := cesr.AppendVarData(nil, cesr.CodeC, ct)
		msg, _ := cesr.AppendCount(nil, cesr.CodeE, (len(env)+len(body))/3)
		msg = append(append(msg, env...), body...)
		sig, _ := sign(alice, msg, nil)
		msg, _ = appendSignatureAttachment(msg, sig)
		_, err = Open(bob, alice.Public(), msg)
		expectKind(t, err, KindSender)
	})

	// TSP 1.0 (§3.2, §3.7 step 7): HPKE-Base no longer lets a confidential
	// payload carry the NULL VID, which Rev 3 allowed.
	t.Run("HPKE-Base requires ESSR sender", func(t *testing.T) {
		sf, _ := appendVID(nil, "")
		env := envFieldsFor(alice.VID, bob.VID)
		frame, _, err := encodePayload(&SCS{Data: []byte("x")}, &frameInput{envFields: env, senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen})
		if err != nil {
			t.Fatal(err)
		}
		ct, err := tspcrypto.HPKEBaseSeal(bob.EncryptionKey, hpkeInfo, env, frame, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := cesr.AppendVarData(nil, cesr.CodeF, ct)
		msg, _ := cesr.AppendCount(nil, cesr.CodeE, (len(env)+len(body))/3)
		msg = append(append(msg, env...), body...)
		sig, _ := sign(alice, msg, nil)
		msg, _ = appendSignatureAttachment(msg, sig)
		_, err = Open(bob, alice.Public(), msg)
		expectKind(t, err, KindSender)
	})

	t.Run("signed-only NULL ESSR sender allowed", func(t *testing.T) {
		packed, err := Pack(alice, bob.Public(), &SCS{Data: []byte("x")}, &PackOptions{Scheme: SchemeSignedOnly, PayloadSender: SenderFieldNull})
		if err != nil {
			t.Fatal(err)
		}
		m, err := Open(bob, alice.Public(), packed.Message)
		if err != nil {
			t.Fatal(err)
		}
		if m.PayloadSender != "" {
			t.Fatalf("payload sender %q, want the NULL VID", m.PayloadSender)
		}
	})

	t.Run("signed-only hop refused", func(t *testing.T) {
		inner, err := Pack(alice, bob.Public(), &SCS{Data: []byte("x")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		sf, _ := appendVID(nil, "")
		frame, _, err := encodePayload(&HOP{Inner: inner.Message}, &frameInput{envFields: envFieldsFor(alice.VID, bob.VID), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(bob, alice.Public(), buildSignedOnly(t, alice, bob.VID, frame))
		expectKind(t, err, KindMalformed)
	})

	t.Run("hop with malformed inner message", func(t *testing.T) {
		_, err := Pack(alice, bob.Public(), &HOP{Inner: []byte("abc")}, nil)
		expectKind(t, err, KindInvalidInput)
	})

	t.Run("unknown payload type", func(t *testing.T) {
		sf, _ := appendVID(nil, "")
		frame, _, _ := encodePayload(&SCS{Data: []byte("x")}, &frameInput{envFields: envFieldsFor(alice.VID, bob.VID), senderField: sf, digestAlg: DigestSHA2256, nonce: nonceGen})
		tag := cesr.Tag("XZZZ")
		copy(frame[3:6], tag[:])
		_, err := Open(bob, alice.Public(), buildSignedOnly(t, alice, bob.VID, frame))
		expectKind(t, err, KindUnsupported)
	})

	t.Run("null receiver signed-only", func(t *testing.T) {
		packed, err := Pack(alice, nil, &RFI{}, &PackOptions{Scheme: SchemeSignedOnly})
		if err != nil {
			t.Fatal(err)
		}
		m, err := Open(bob, alice.Public(), packed.Message)
		if err != nil {
			t.Fatal(err)
		}
		if m.Receiver != "" {
			t.Fatal("receiver should be NULL")
		}
		_, err = Pack(alice, nil, &RFI{}, nil)
		expectKind(t, err, KindInvalidInput)
	})
}

func TestIdentityValidation(t *testing.T) {
	alice, bob := classicPair(t)
	bad := *alice
	bad.SigningKey = bob.SigningKey
	expectKind(t, bad.Validate(), KindInvalidInput)
	if _, err := Pack(&bad, bob.Public(), &SCS{}, nil); err == nil {
		t.Fatal("packed with a mismatched key pair")
	}
	short := *bob.Public()
	short.EncryptionKey = short.EncryptionKey[:31]
	expectKind(t, short.Validate(), KindInvalidInput)
	if !errors.Is(short.Validate(), ErrInvalidInput) {
		t.Fatal("errors.Is sentinel")
	}
	_, err := Pack(alice, bob.Public(), &SCS{}, &PackOptions{Scheme: SchemeHPKEPQ})
	expectKind(t, err, KindInvalidInput)
}

// An XSCS body is exactly one Bytes primitive (spec issue #77): an -H##
// interleaved group, or a second primitive, is refused rather than truncated.
func TestStreamIsOneBytesPrimitive(t *testing.T) {
	prim := func(b []byte) []byte { p, _ := cesr.AppendVarData(nil, cesr.CodeB, b); return p }
	frameOf := func(stream []byte) []byte {
		tag := cesr.Tag("XSCS")
		body := append([]byte{}, tag[:]...)
		body = append(body, prim(nil)...) // NULL sender
		body = append(body, prim(nil)...) // no padding
		body, _ = cesr.AppendCount(body, cesr.CodeA, len(stream)/3)
		body = append(body, stream...)
		f, _ := cesr.AppendCount(nil, cesr.CodeZ, len(body)/3)
		return append(f, body...)
	}
	if _, err := decodePayload(frameOf(prim([]byte("hello world"))), nil); err != nil {
		t.Fatalf("single Bytes primitive refused: %v", err)
	}
	json := prim([]byte(`{"hello":"world"}`))
	hgroup, _ := cesr.AppendCount(nil, byte(cesr.Int("H")), len(json)/3)
	for name, stream := range map[string][]byte{
		"-H group":       append(hgroup, json...),
		"two primitives": append(prim([]byte("one")), prim([]byte("two"))...),
	} {
		if _, err := decodePayload(frameOf(stream), nil); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want malformed", name, err)
		}
	}
}
