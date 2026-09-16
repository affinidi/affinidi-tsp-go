package tsp

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/affinidi/affinidi-tsp-go/cesr"
)

// Version is a TSP protocol version, MAJOR.MINOR.
type Version struct {
	Major, Minor int
}

// CurrentVersion is the version this package emits: 0.2, encoded YTSP-AAC.
var CurrentVersion = Version{Major: 0, Minor: 2}

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Scheme is how a message's payload is protected.
type Scheme uint8

// Schemes.
const (
	// SchemeAuto selects HPKE by the receiver's encryption key type: HPKE-Base
	// for X25519, HPKE-PQ for MLKEM768-X25519. Only meaningful for Pack.
	SchemeAuto Scheme = iota
	// SchemeHPKEBase is HPKE-Base with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
	// and ChaCha20Poly1305 (ciphertext code F).
	SchemeHPKEBase
	// SchemeHPKEPQ is HPKE-Base with the MLKEM768-X25519 hybrid KEM (ciphertext
	// code F; distinguished only by the receiver's key type).
	SchemeHPKEPQ
	// SchemeSealedBox is the libsodium anonymous sealed box (ciphertext code C).
	SchemeSealedBox
	// SchemeSignedOnly carries the payload in the clear, signed.
	SchemeSignedOnly
)

func (s Scheme) String() string {
	switch s {
	case SchemeAuto:
		return "auto"
	case SchemeHPKEBase:
		return "hpke-base"
	case SchemeHPKEPQ:
		return "hpke-pq"
	case SchemeSealedBox:
		return "sealed-box"
	case SchemeSignedOnly:
		return "signed-only"
	}
	return fmt.Sprintf("Scheme(%d)", uint8(s))
}

// Confidential reports whether the scheme encrypts the payload.
func (s Scheme) Confidential() bool { return s != SchemeSignedOnly }

// DigestAlg is the hash function of a TSP digest, identified on the wire by the
// digest's CESR code.
type DigestAlg uint8

// Digest algorithms.
const (
	// DigestDefault selects the scheme's algorithm: Blake2b-256 under the
	// sealed box, SHA2-256 otherwise. Only meaningful as an input.
	DigestDefault    DigestAlg = iota
	DigestSHA2256              // CESR code I
	DigestBlake2b256           // CESR code F
)

func (a DigestAlg) String() string {
	switch a {
	case DigestSHA2256:
		return "sha2-256"
	case DigestBlake2b256:
		return "blake2b-256"
	}
	return "default"
}

func (a DigestAlg) code() uint32 {
	if a == DigestBlake2b256 {
		return uint32(cesr.CodeF)
	}
	return uint32(cesr.CodeI)
}

// Digest is a TSP digest: a 256-bit hash and the algorithm that produced it.
type Digest struct {
	Alg   DigestAlg
	Value [32]byte
}

// Equal reports whether two digests are identical, in constant time with
// respect to the value.
func (d Digest) Equal(o Digest) bool {
	return d.Alg == o.Alg && subtle.ConstantTimeCompare(d.Value[:], o.Value[:]) == 1
}

// Compare orders digests lexicographically by their binary-domain value, the
// order the RFI race tie-break uses.
func (d Digest) Compare(o Digest) int { return bytes.Compare(d.Value[:], o.Value[:]) }

func (d Digest) String() string { return fmt.Sprintf("%s:%x", d.Alg, d.Value) }

// PayloadType is a TSP payload type code.
type PayloadType uint8

// Payload types.
const (
	PayloadSCS PayloadType = iota + 1 // XSCS, upper-layer application payload
	PayloadCTL                        // XCTL, generic control payload
	PayloadPAD                        // XPAD, padding message
	PayloadRFI                        // XRFI, relationship forming invite
	PayloadRFA                        // XRFA, relationship forming accept
	PayloadRFD                        // XRFD, relationship forming decline / cancel
	PayloadHOP                        // XHOP, nested or routed message
)

var payloadTags = map[PayloadType][3]byte{
	PayloadSCS: cesr.Tag("XSCS"),
	PayloadCTL: cesr.Tag("XCTL"),
	PayloadPAD: cesr.Tag("XPAD"),
	PayloadRFI: cesr.Tag("XRFI"),
	PayloadRFA: cesr.Tag("XRFA"),
	PayloadRFD: cesr.Tag("XRFD"),
	PayloadHOP: cesr.Tag("XHOP"),
}

func (t PayloadType) String() string {
	switch t {
	case PayloadSCS:
		return "XSCS"
	case PayloadCTL:
		return "XCTL"
	case PayloadPAD:
		return "XPAD"
	case PayloadRFI:
		return "XRFI"
	case PayloadRFA:
		return "XRFA"
	case PayloadRFD:
		return "XRFD"
	case PayloadHOP:
		return "XHOP"
	}
	return fmt.Sprintf("PayloadType(%d)", uint8(t))
}

// Payload is one of *SCS, *CTL, *PAD, *RFI, *RFA, *RFD or *HOP.
type Payload interface {
	Type() PayloadType
	isPayload()
}

// NonceSize is the length of a TSP nonce (128 bits).
const NonceSize = 16

// SCS is an upper-layer application payload (XSCS).
type SCS struct {
	// Data is the application bytes, carried as exactly one CESR Bytes
	// primitive inside the -A## stream. Its format is the upper layer's; Open
	// rejects a stream holding anything else (spec issue #77).
	Data []byte
}

// CTL is a generic control payload (XCTL) for the layer above TSP. It has the
// same shape as SCS.
type CTL struct {
	Data []byte
}

// PAD is a padding message (XPAD). Pad the message with PackOptions.Padding.
type PAD struct {
	// Nonce is 16 bytes. On Pack a nil Nonce is filled from the random source.
	Nonce []byte
}

// Referral is the Referral_Field of an invite: a new VID introduced over an
// existing relationship, with that VID's own signature over the invite.
type Referral struct {
	VID string
	// Signature is a 64-byte Ed25519 or 3309-byte ML-DSA-65 signature. On Pack,
	// a nil Signature is produced with PackOptions.ReferralSigner.
	Signature []byte
}

// RFI is a relationship forming invite (XRFI).
type RFI struct {
	// Nonce is 16 bytes. On Pack a nil Nonce is filled from the random source.
	Nonce []byte
	// ReplyPath is the route for the accept; empty for a direct reply.
	ReplyPath []string
	// Referral, when non-nil, introduces a new VID (parallel relationship
	// forming).
	Referral *Referral
	// Digest is the invite's own SAID. Computed by Pack and verified by Open;
	// ignored on input.
	Digest Digest
}

// RFA is a relationship forming accept (XRFA).
type RFA struct {
	// InviteDigest is the Digest of the invite being accepted, echoed verbatim.
	InviteDigest Digest
	// ReplyDigest is the accept's own SAID. Computed by Pack and verified by
	// Open; ignored on input.
	ReplyDigest Digest
}

// RFD is a relationship forming decline or cancel (XRFD).
type RFD struct {
	// Digest names the relationship: the invite's Digest or the accept's
	// Reply_Digest. A DigestDefault algorithm on input means SHA2-256.
	Digest Digest
}

// HOP carries a complete inner TSP message (XHOP): nested when Hops is empty,
// routed otherwise.
type HOP struct {
	Hops  []string
	Inner []byte
}

func (*SCS) Type() PayloadType { return PayloadSCS }
func (*CTL) Type() PayloadType { return PayloadCTL }
func (*PAD) Type() PayloadType { return PayloadPAD }
func (*RFI) Type() PayloadType { return PayloadRFI }
func (*RFA) Type() PayloadType { return PayloadRFA }
func (*RFD) Type() PayloadType { return PayloadRFD }
func (*HOP) Type() PayloadType { return PayloadHOP }

func (*SCS) isPayload() {}
func (*CTL) isPayload() {}
func (*PAD) isPayload() {}
func (*RFI) isPayload() {}
func (*RFA) isPayload() {}
func (*RFD) isPayload() {}
func (*HOP) isPayload() {}
