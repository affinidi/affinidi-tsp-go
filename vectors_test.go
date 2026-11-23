package tsp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// The Appendix A vectors of TSP 1.0 (YTSP-BAA), as published in the released
// specification (tswg-tsp-specification ccda6b3) and in testdata/spec-vectors.json,
// identical to affinidi-tsp's and vti-tsp-js's. Values are qb64;
// base64url-decoding gives the binary-domain wire bytes.

type vectorIdentity struct {
	ID         string `json:"id"`
	LongForm   string `json:"longForm"`
	SigKeyType string `json:"sigKeyType"`
	PkS        string `json:"pkS"`
	SkS        string `json:"skS"`
	EncKeyType string `json:"encKeyType"`
	PkE        string `json:"pkE"`
	SkE        string `json:"skE"`
}

type vector struct {
	Sender       string `json:"sender"`
	Receiver     string `json:"receiver"`
	IkmE         string `json:"ikmE"`
	SkEm         string `json:"skEm"`
	PkEm         string `json:"pkEm"`
	Message      string `json:"message"`
	Payload      string `json:"payload"`
	InnerPayload string `json:"innerPayload"`
	NewVid       string `json:"newVid"`
	SignatureNew string `json:"signatureNew"`
}

type vectorFile struct {
	Identifiers map[string]vectorIdentity `json:"identifiers"`
	Vectors     map[string]vector         `json:"vectors"`
}

func loadVectors(t testing.TB) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/spec-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	return &vf
}

func b64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}

func (vf *vectorFile) identity(t testing.TB, name string) *PrivateIdentity {
	t.Helper()
	vi, ok := vf.Identifiers[name]
	if !ok {
		t.Fatalf("no identifier %q", name)
	}
	p := &PrivateIdentity{
		Identity: Identity{
			VID:           vi.ID,
			SigningKey:    b64(t, vi.PkS),
			EncryptionKey: b64(t, vi.PkE),
		},
		SigningPrivateKey:    b64(t, vi.SkS),
		DecryptionPrivateKey: b64(t, vi.SkE),
	}
	switch vi.SigKeyType {
	case "Ed25519":
		p.SigKeyType = SigKeyEd25519
	case "MlDsa65":
		p.SigKeyType = SigKeyMLDSA65
	}
	switch vi.EncKeyType {
	case "X25519":
		p.EncKeyType = EncKeyX25519
	case "MLKEM768-X25519":
		p.EncKeyType = EncKeyMLKEM768X25519
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("identity %s: %v", name, err)
	}
	return p
}

func TestSpecVectors(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Vectors) != 11 {
		t.Fatalf("expected 11 vectors, got %d", len(vf.Vectors))
	}
	for name, v := range vf.Vectors {
		t.Run(name, func(t *testing.T) {
			sender := vf.identity(t, v.Sender)
			receiver := vf.identity(t, v.Receiver)
			msg := b64(t, v.Message)

			env, err := Peek(msg)
			if err != nil {
				t.Fatalf("Peek: %v", err)
			}
			if env.Sender != sender.VID || env.Receiver != receiver.VID || env.Version != CurrentVersion {
				t.Fatalf("Peek: unexpected envelope %+v", env)
			}

			opened, err := Open(receiver, sender.Public(), msg)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			// The fixture's plaintext payload frame decodes to the same payload.
			want, err := decodePayload(b64(t, v.Payload), mustParse(t, msg).envFields)
			if err != nil {
				t.Fatalf("decoding fixture payload: %v", err)
			}
			if !payloadEqual(want.payload, opened.Payload) || want.payloadSender != opened.PayloadSender || !bytes.Equal(want.padding, opened.Padding) {
				t.Fatalf("opened payload %#v differs from fixture payload %#v", opened.Payload, want.payload)
			}
			checkVectorPayload(t, vf, name, opened)

			// Re-encoding the opened payload reproduces the fixture's payload frame.
			frame, _, err := encodePayload(opened.Payload, &frameInput{
				envFields:   mustParse(t, msg).envFields,
				senderField: mustVID(t, opened.PayloadSender),
				padding:     opened.Padding,
				digestAlg:   digestAlgOf(opened.Payload, opened.Scheme),
			})
			if err != nil {
				t.Fatalf("encodePayload: %v", err)
			}
			if !bytes.Equal(frame, b64(t, v.Payload)) {
				t.Fatalf("re-encoded payload frame differs from the fixture")
			}

			// Where the ephemeral key material is published, re-packing
			// reproduces the message byte for byte.
			if v.IkmE == "" && v.SkEm == "" && opened.Scheme != SchemeSignedOnly {
				t.Logf("no ephemeral material published: open-only")
				repackRoundTrip(t, sender, receiver, opened)
				return
			}
			opts := &PackOptions{
				Scheme:        opened.Scheme,
				Padding:       opened.Padding,
				PayloadSender: SenderFieldNull,
				DigestAlg:     digestAlgOf(opened.Payload, opened.Scheme),
			}
			if opened.PayloadSender != "" {
				opts.PayloadSender = SenderFieldPresent
			}
			if v.IkmE != "" {
				opts.Ephemeral = b64(t, v.IkmE)
			}
			if v.SkEm != "" {
				opts.Ephemeral = b64(t, v.SkEm)
			}
			packed, err := Pack(sender, receiver.Public(), opened.Payload, opts)
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if !bytes.Equal(packed.Message, msg) {
				t.Fatalf("re-packed message differs from the vector\n got %s\nwant %s",
					base64.RawURLEncoding.EncodeToString(packed.Message), v.Message)
			}
			if v.PkEm != "" && !bytes.Contains(msg, b64(t, v.PkEm)) {
				t.Fatalf("pkEm not found in the message")
			}
		})
	}
}

func repackRoundTrip(t *testing.T, sender, receiver *PrivateIdentity, opened *Message) {
	t.Helper()
	packed, err := Pack(sender, receiver.Public(), opened.Payload, &PackOptions{Scheme: opened.Scheme})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	again, err := Open(receiver, sender.Public(), packed.Message)
	if err != nil {
		t.Fatalf("Open of re-packed message: %v", err)
	}
	if !payloadEqual(again.Payload, opened.Payload) {
		t.Fatalf("round trip changed the payload")
	}
}

func checkVectorPayload(t *testing.T, vf *vectorFile, name string, m *Message) {
	t.Helper()
	nonce := bytes.Repeat([]byte{0x11}, 16)
	switch name {
	case "direct-sealed-box":
		expectSCS(t, m, "hello world", SchemeSealedBox, m.Sender)
	case "direct-hpke-base":
		expectSCS(t, m, "hello world", SchemeHPKEBase, m.Sender)
	case "direct-hpke-base-pq":
		expectSCS(t, m, "hello world", SchemeHPKEPQ, m.Sender)
	case "direct-signed-only":
		expectSCS(t, m, "public announcement!", SchemeSignedOnly, "")
	case "control-rfi-direct", "control-rfi-sealed-box":
		rfi, ok := m.Payload.(*RFI)
		if !ok {
			t.Fatalf("payload %T", m.Payload)
		}
		if !bytes.Equal(rfi.Nonce, nonce) || len(rfi.ReplyPath) != 0 || rfi.Referral != nil {
			t.Fatalf("unexpected invite %+v", rfi)
		}
		wantAlg := DigestSHA2256
		if name == "control-rfi-sealed-box" {
			wantAlg = DigestBlake2b256
			if m.PayloadSender != m.Sender {
				t.Fatalf("sealed-box invite must carry the ESSR sender")
			}
		}
		if rfi.Digest.Alg != wantAlg {
			t.Fatalf("digest algorithm %v, want %v", rfi.Digest.Alg, wantAlg)
		}
	case "control-rfi-referral":
		// §7.2.5: an invite over an existing relationship that introduces a new
		// VID, with Signature_new by that VID's key.
		rfi, ok := m.Payload.(*RFI)
		if !ok {
			t.Fatalf("payload %T", m.Payload)
		}
		v := vf.Vectors[name]
		introduced := vf.identity(t, v.NewVid)
		// The referral names the introduced did:peer:4 in its long form.
		if lf := vf.Identifiers[v.NewVid].LongForm; lf != "" {
			introduced.VID = lf
		}
		if rfi.Referral == nil || rfi.Referral.VID != introduced.VID {
			t.Fatalf("referral %+v, want VID %s", rfi.Referral, introduced.VID)
		}
		if !bytes.Equal(rfi.Referral.Signature, b64(t, v.SignatureNew)) {
			t.Fatalf("Signature_new differs from the vector")
		}
		if m.PayloadSender != m.Sender {
			t.Fatalf("a TSP 1.0 confidential payload must carry the ESSR sender")
		}
		if err := VerifyReferral(m, introduced.Public()); err != nil {
			t.Fatalf("VerifyReferral: %v", err)
		}
		tampered := *m
		tamperedRFI := *rfi
		tamperedRef := *rfi.Referral
		tamperedRef.Signature = append([]byte(nil), rfi.Referral.Signature...)
		tamperedRef.Signature[0] ^= 1
		tamperedRFI.Referral = &tamperedRef
		tampered.Payload = &tamperedRFI
		if err := VerifyReferral(&tampered, introduced.Public()); err == nil {
			t.Fatalf("VerifyReferral accepted a tampered Signature_new")
		}
	case "control-rfa-direct", "control-rfd":
		rfiMsg := openVector(t, vf, "control-rfi-direct")
		inviteDigest := rfiMsg.Payload.(*RFI).Digest
		switch p := m.Payload.(type) {
		case *RFA:
			if !p.InviteDigest.Equal(inviteDigest) {
				t.Fatalf("accept does not echo the invite digest")
			}
			if p.ReplyDigest.Alg != DigestSHA2256 || p.ReplyDigest.Equal(inviteDigest) {
				t.Fatalf("unexpected reply digest %v", p.ReplyDigest)
			}
		case *RFD:
			if !p.Digest.Equal(inviteDigest) {
				t.Fatalf("cancel does not name the invite digest")
			}
		default:
			t.Fatalf("payload %T", m.Payload)
		}
	case "nested-direct", "routed":
		hop, ok := m.Payload.(*HOP)
		if !ok {
			t.Fatalf("payload %T", m.Payload)
		}
		var wantHops []string
		if name == "routed" {
			wantHops = []string{vf.Identifiers["q"].ID, vf.Identifiers["nested_bob"].ID}
		}
		if len(hop.Hops) != len(wantHops) {
			t.Fatalf("hops %v, want %v", hop.Hops, wantHops)
		}
		for i := range wantHops {
			if hop.Hops[i] != wantHops[i] {
				t.Fatalf("hops %v, want %v", hop.Hops, wantHops)
			}
		}
		inner, err := Open(vf.identity(t, "nested_bob"), vf.identity(t, "nested_alice").Public(), hop.Inner)
		if err != nil {
			t.Fatalf("opening inner message: %v", err)
		}
		expectSCS(t, inner, "hello world", SchemeHPKEBase, inner.Sender)
	default:
		t.Fatalf("no expectations for vector %s", name)
	}
}

func openVector(t *testing.T, vf *vectorFile, name string) *Message {
	t.Helper()
	v := vf.Vectors[name]
	m, err := Open(vf.identity(t, v.Receiver), vf.identity(t, v.Sender).Public(), b64(t, v.Message))
	if err != nil {
		t.Fatalf("Open %s: %v", name, err)
	}
	return m
}

func expectSCS(t *testing.T, m *Message, data string, scheme Scheme, payloadSender string) {
	t.Helper()
	scs, ok := m.Payload.(*SCS)
	if !ok {
		t.Fatalf("payload %T, want *SCS", m.Payload)
	}
	if string(scs.Data) != data || m.Scheme != scheme || m.PayloadSender != payloadSender || len(m.Padding) != 0 {
		t.Fatalf("got data %q scheme %v sender %q; want %q %v %q", scs.Data, m.Scheme, m.PayloadSender, data, scheme, payloadSender)
	}
}

func mustParse(t *testing.T, msg []byte) *parsedMessage {
	t.Helper()
	pm, err := parseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return pm
}

func mustVID(t *testing.T, vid string) []byte {
	t.Helper()
	b, err := appendVID(nil, vid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func digestAlgOf(p Payload, s Scheme) DigestAlg {
	switch p := p.(type) {
	case *RFI:
		return p.Digest.Alg
	case *RFA:
		return p.ReplyDigest.Alg
	}
	if s == SchemeSealedBox {
		return DigestBlake2b256
	}
	return DigestSHA2256
}

func payloadEqual(a, b Payload) bool {
	switch a := a.(type) {
	case *SCS:
		b, ok := b.(*SCS)
		return ok && bytes.Equal(a.Data, b.Data)
	case *CTL:
		b, ok := b.(*CTL)
		return ok && bytes.Equal(a.Data, b.Data)
	case *PAD:
		b, ok := b.(*PAD)
		return ok && bytes.Equal(a.Nonce, b.Nonce)
	case *RFI:
		b, ok := b.(*RFI)
		if !ok || !bytes.Equal(a.Nonce, b.Nonce) || !a.Digest.Equal(b.Digest) || len(a.ReplyPath) != len(b.ReplyPath) {
			return false
		}
		for i := range a.ReplyPath {
			if a.ReplyPath[i] != b.ReplyPath[i] {
				return false
			}
		}
		if (a.Referral == nil) != (b.Referral == nil) {
			return false
		}
		return a.Referral == nil || (a.Referral.VID == b.Referral.VID && bytes.Equal(a.Referral.Signature, b.Referral.Signature))
	case *RFA:
		b, ok := b.(*RFA)
		return ok && a.InviteDigest.Equal(b.InviteDigest) && a.ReplyDigest.Equal(b.ReplyDigest)
	case *RFD:
		b, ok := b.(*RFD)
		return ok && a.Digest.Equal(b.Digest)
	case *HOP:
		b, ok := b.(*HOP)
		if !ok || !bytes.Equal(a.Inner, b.Inner) || len(a.Hops) != len(b.Hops) {
			return false
		}
		for i := range a.Hops {
			if a.Hops[i] != b.Hops[i] {
				return false
			}
		}
		return true
	}
	return false
}
