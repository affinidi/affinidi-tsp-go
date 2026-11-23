// Package cesr implements the binary-domain (qb2) CESR primitives that the
// Trust Spanning Protocol uses to frame its messages.
//
// TSP never interprets CESR in general: it uses a small, closed set of codes
// from the master code table for genus -_AAACAA (TSP 1.0, "Serialization
// and Encoding"). This package implements exactly those, in the binary
// domain, with canonical-encoding checks on every read:
//
//   - count codes (-X## / --X#####), whose count is a length in quadlets;
//   - variable-length data (4X## / 5X## / 6X## short, 7AAX#### / 8AAX#### /
//     9AAX#### long), whose selector carries the number of zero lead bytes;
//   - fixed-length data (X, 0X, 1XXX), sized by the payload length;
//   - the indexed Ed25519 signature (B#);
//   - the TSP version code YTSP-###.
//
// Readers are strict: a primitive must use the shortest form that can hold
// its value, lead bytes and pad bits must be zero, and sizes are bounded.
// Nothing here panics on untrusted input.
package cesr

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// Errors returned by the readers. They are wrapped with context; test with
// errors.Is.
var (
	// ErrTruncated reports that a primitive runs past the end of its input.
	ErrTruncated = errors.New("cesr: truncated primitive")
	// ErrUnexpectedCode reports that the bytes are not the expected primitive.
	ErrUnexpectedCode = errors.New("cesr: unexpected code")
	// ErrNonCanonical reports a primitive that decodes but is not in its
	// canonical form (non-zero lead bytes or pad bits, or a long form used for a
	// value the short form holds).
	ErrNonCanonical = errors.New("cesr: non-canonical encoding")
	// ErrTooLarge reports a size beyond what the code (or this package's
	// bounds) can carry.
	ErrTooLarge = errors.New("cesr: primitive too large")
)

// Base64 selector values: the index of a character in the base64url alphabet.
const (
	selD0   = 52 // '0'
	selD1   = 53 // '1'
	selD4   = 56 // '4'
	selD7   = 59 // '7'
	selDash = 62 // '-'
)

// Identifiers (base64url indices) of the codes TSP uses.
const (
	CodeA byte = 0  // -A generic stream count; 0A nonce
	CodeB byte = 1  // 4B.. bytes / VID; B# indexed Ed25519 signature
	CodeC byte = 2  // -C attachment group; 4C.. sealed-box ciphertext
	CodeE byte = 4  // -E TSP envelope
	CodeF byte = 5  // 4F.. HPKE ciphertext; F Blake2b-256 digest
	CodeI byte = 8  // I SHA2-256 digest
	CodeJ byte = 9  // -J VID list
	CodeK byte = 10 // -K indexed signature group
	CodeZ byte = 25 // -Z TSP payload
)

// CodeMLDSA65 is the 18-bit identifier of the ML-DSA-65 signature code 1AAQ
// (provisional, see TSP 1.0 "ML-DSA-65 Signature").
const CodeMLDSA65 uint32 = 16 // "AAQ"

const (
	// MaxShortCount is the largest count a two-character count code holds.
	MaxShortCount = 64*64 - 1
	// MaxLongCount is the largest count a five-character count code holds.
	MaxLongCount = 1<<30 - 1
	// MaxVarDataSize bounds a single variable-data primitive (bytes). It is
	// the largest size the long form can carry, 3 * (2^24 - 1).
	MaxVarDataSize = 3 * (1<<24 - 1)
)

// Int returns the big-endian integer value of a base64url string, as used to
// derive CESR code identifiers. It returns -1 for a non-base64url character.
func Int(s string) int64 {
	var acc int64
	for i := 0; i < len(s); i++ {
		v := b64Index(s[i])
		if v < 0 {
			return -1
		}
		acc = acc<<6 | int64(v)
	}
	return acc
}

func b64Index(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	}
	return -1
}

// Tag returns the 3-byte binary form of a 4-character CESR code such as
// "XSCS" or "YTSP". It panics if s is not four base64url characters; it is
// meant for package-level constants.
func Tag(s string) [3]byte {
	v := Int(s)
	if len(s) != 4 || v < 0 {
		panic("cesr: Tag requires four base64url characters")
	}
	return [3]byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

func triplet(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func appendTriplet(dst []byte, w uint32) []byte {
	return append(dst, byte(w>>16), byte(w>>8), byte(w))
}

// ---------------------------------------------------------------------------
// Count codes

// CountSize returns the encoded length of a count code holding count.
func CountSize(count int) int {
	if count <= MaxShortCount {
		return 3
	}
	return 6
}

// AppendCount appends the count code -X## (or --X##### when count does not
// fit the short form) for identifier code.
func AppendCount(dst []byte, code byte, count int) ([]byte, error) {
	if code >= 64 {
		return dst, fmt.Errorf("%w: count code identifier %d", ErrUnexpectedCode, code)
	}
	switch {
	case count < 0:
		return dst, fmt.Errorf("%w: negative count", ErrTooLarge)
	case count <= MaxShortCount:
		return appendTriplet(dst, selDash<<18|uint32(code)<<12|uint32(count)), nil
	case count <= MaxLongCount:
		dst = appendTriplet(dst, selDash<<18|selDash<<12|uint32(code)<<6|uint32(count>>24))
		return appendTriplet(dst, uint32(count)&0xFFFFFF), nil
	}
	return dst, fmt.Errorf("%w: count %d", ErrTooLarge, count)
}

// ReadCount reads a count code for identifier code at the start of src and
// returns the count and the number of bytes consumed.
func ReadCount(src []byte, code byte) (count, n int, err error) {
	if len(src) < 3 {
		return 0, 0, ErrTruncated
	}
	w := triplet(src)
	if w>>18 != selDash {
		return 0, 0, fmt.Errorf("%w: want count code -%c", ErrUnexpectedCode, b64Char(code))
	}
	if (w>>12)&0x3F == uint32(code) && code != selDash {
		return int(w & 0xFFF), 3, nil
	}
	if (w>>12)&0x3F == selDash && (w>>6)&0x3F == uint32(code) {
		if len(src) < 6 {
			return 0, 0, ErrTruncated
		}
		c := int(w&0x3F)<<24 | int(triplet(src[3:]))
		if c <= MaxShortCount {
			return 0, 0, fmt.Errorf("%w: long count code for count %d", ErrNonCanonical, c)
		}
		return c, 6, nil
	}
	return 0, 0, fmt.Errorf("%w: want count code -%c", ErrUnexpectedCode, b64Char(code))
}

func b64Char(v byte) byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return alphabet[v&0x3F]
}

// ---------------------------------------------------------------------------
// Variable-length data

// VarDataSize returns the encoded length of a variable-data primitive holding
// n bytes.
func VarDataSize(n int) int {
	padded := (n + 2) / 3 * 3
	if padded/3 <= MaxShortCount {
		return 3 + padded
	}
	return 6 + padded
}

// AppendVarData appends data as a variable-length primitive with identifier
// code: 4X## / 5X## / 6X## (or 7AAX#### / 8AAX#### / 9AAX####), followed by
// 0-2 zero lead bytes and the data.
func AppendVarData(dst []byte, code byte, data []byte) ([]byte, error) {
	if code >= 64 {
		return dst, fmt.Errorf("%w: identifier %d", ErrUnexpectedCode, code)
	}
	if len(data) > MaxVarDataSize {
		return dst, fmt.Errorf("%w: %d bytes of variable data", ErrTooLarge, len(data))
	}
	lead := (3 - len(data)%3) % 3
	size := uint32((len(data) + lead) / 3)
	if size <= MaxShortCount {
		dst = appendTriplet(dst, uint32(selD4+lead)<<18|uint32(code)<<12|size)
	} else {
		dst = appendTriplet(dst, uint32(selD7+lead)<<18|uint32(code))
		dst = appendTriplet(dst, size)
	}
	dst = append(dst, make([]byte, lead)...)
	return append(dst, data...), nil
}

// ReadVarData reads a variable-length primitive with identifier code at the
// start of src. It returns the data (a sub-slice of src) and the number of
// bytes consumed.
func ReadVarData(src []byte, code byte) (data []byte, n int, err error) {
	if len(src) < 3 {
		return nil, 0, ErrTruncated
	}
	w := triplet(src)
	sel := w >> 18
	var lead, hdr int
	var size uint32
	switch {
	case sel >= selD4 && sel <= selD4+2:
		if (w>>12)&0x3F != uint32(code) {
			return nil, 0, fmt.Errorf("%w: variable data code %d", ErrUnexpectedCode, (w>>12)&0x3F)
		}
		lead, hdr, size = int(sel-selD4), 3, w&0xFFF
	case sel >= selD7 && sel <= selD7+2:
		if w&0x3FFFF != uint32(code) {
			return nil, 0, fmt.Errorf("%w: variable data code %d", ErrUnexpectedCode, w&0x3FFFF)
		}
		if len(src) < 6 {
			return nil, 0, ErrTruncated
		}
		lead, hdr, size = int(sel-selD7), 6, triplet(src[3:])
		if size <= MaxShortCount {
			return nil, 0, fmt.Errorf("%w: long variable data form for %d triplets", ErrNonCanonical, size)
		}
	default:
		return nil, 0, fmt.Errorf("%w: not a variable data primitive", ErrUnexpectedCode)
	}
	total := int(size) * 3
	if total < lead {
		// A zero-size primitive cannot carry lead bytes.
		return nil, 0, fmt.Errorf("%w: lead bytes exceed size", ErrNonCanonical)
	}
	if hdr+total > len(src) {
		return nil, 0, ErrTruncated
	}
	for _, b := range src[hdr : hdr+lead] {
		if b != 0 {
			return nil, 0, fmt.Errorf("%w: non-zero lead byte", ErrNonCanonical)
		}
	}
	return src[hdr+lead : hdr+total], hdr + total, nil
}

// PeekVarDataCode reports whether src starts with a variable-length primitive
// header carrying identifier code (short or long form). It does not validate
// the rest of the primitive.
func PeekVarDataCode(src []byte, code byte) bool {
	if len(src) < 3 {
		return false
	}
	w := triplet(src)
	sel := w >> 18
	switch {
	case sel >= selD4 && sel <= selD4+2:
		return (w>>12)&0x3F == uint32(code)
	case sel >= selD7 && sel <= selD7+2:
		return w&0x3FFFF == uint32(code)
	}
	return false
}

// ---------------------------------------------------------------------------
// Fixed-length data

// fixedHeader returns the header bytes for fixed data of length n with the
// given identifier: one character (n%3 == 2), two characters (n%3 == 1) or four
// characters (n%3 == 0).
func fixedHeader(code uint32, n int) ([]byte, error) {
	switch (n + 1) % 3 {
	case 0: // header 1 byte: 6-bit code + 2 pad bits
		if code >= 64 {
			return nil, fmt.Errorf("%w: one-character code %d", ErrUnexpectedCode, code)
		}
		return []byte{byte(code << 2)}, nil
	case 2: // header 2 bytes: '0' + 6-bit code + 4 pad bits
		if code >= 64 {
			return nil, fmt.Errorf("%w: two-character code %d", ErrUnexpectedCode, code)
		}
		w := uint32(selD0)<<18 | code<<12
		return []byte{byte(w >> 16), byte(w >> 8)}, nil
	default: // header 3 bytes: '1' + 18-bit code
		if code >= 1<<18 {
			return nil, fmt.Errorf("%w: four-character code %d", ErrUnexpectedCode, code)
		}
		w := uint32(selD1)<<18 | code
		return []byte{byte(w >> 16), byte(w >> 8), byte(w)}, nil
	}
}

// FixedSize returns the encoded length of a fixed-data primitive of n bytes.
func FixedSize(n int) int {
	return (n + 1 + 2) / 3 * 3
}

// AppendFixed appends data as a fixed-length primitive with identifier code.
// The code form (X, 0X or 1XXX) follows from len(data).
func AppendFixed(dst []byte, code uint32, data []byte) ([]byte, error) {
	h, err := fixedHeader(code, len(data))
	if err != nil {
		return dst, err
	}
	dst = append(dst, h...)
	return append(dst, data...), nil
}

// ReadFixed reads a fixed-length primitive of size bytes with identifier code
// from the start of src, requiring an exact header match (pad bits zero).
func ReadFixed(src []byte, code uint32, size int) (data []byte, n int, err error) {
	h, err := fixedHeader(code, size)
	if err != nil {
		return nil, 0, err
	}
	total := len(h) + size
	if len(src) < total {
		return nil, 0, ErrTruncated
	}
	for i := range h {
		if src[i] != h[i] {
			return nil, 0, fmt.Errorf("%w: fixed data header", ErrUnexpectedCode)
		}
	}
	return src[len(h):total], total, nil
}

// ---------------------------------------------------------------------------
// Indexed Ed25519 signature

// IndexedEd25519Size is the encoded length of an indexed Ed25519 signature.
const IndexedEd25519Size = 66

// AppendIndexedEd25519 appends the indexed Ed25519 signature primitive B#.
func AppendIndexedEd25519(dst []byte, index byte, sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return dst, fmt.Errorf("%w: Ed25519 signature of %d bytes", ErrTooLarge, len(sig))
	}
	if index >= 64 {
		return dst, fmt.Errorf("%w: signature index %d", ErrTooLarge, index)
	}
	w := uint32(CodeB)<<18 | uint32(index)<<12
	dst = append(dst, byte(w>>16), byte(w>>8))
	return append(dst, sig...), nil
}

// ReadIndexedEd25519 reads an indexed Ed25519 signature primitive.
func ReadIndexedEd25519(src []byte) (index byte, sig []byte, n int, err error) {
	if len(src) < 2 {
		return 0, nil, 0, ErrTruncated
	}
	w := uint32(src[0])<<16 | uint32(src[1])<<8
	if w>>18 != uint32(CodeB) {
		return 0, nil, 0, fmt.Errorf("%w: not an indexed Ed25519 signature", ErrUnexpectedCode)
	}
	if w&0xFFF != 0 {
		return 0, nil, 0, fmt.Errorf("%w: signature pad bits", ErrNonCanonical)
	}
	if len(src) < IndexedEd25519Size {
		return 0, nil, 0, ErrTruncated
	}
	return byte((w >> 12) & 0x3F), src[2:IndexedEd25519Size], IndexedEd25519Size, nil
}

// ---------------------------------------------------------------------------
// Version

// YTSP is the binary form of the TSP genus/protocol code.
var YTSP = Tag("YTSP")

// VersionSize is the encoded length of the TSP version code.
const VersionSize = 6

// AppendVersion appends YTSP-### for (major, minor): one character of MAJOR
// and two of MINOR.
func AppendVersion(dst []byte, major, minor int) ([]byte, error) {
	if major < 0 || major >= 64 || minor < 0 || minor > MaxShortCount {
		return dst, fmt.Errorf("%w: version %d.%d", ErrTooLarge, major, minor)
	}
	dst = append(dst, YTSP[:]...)
	return appendTriplet(dst, selDash<<18|uint32(major)<<12|uint32(minor)), nil
}

// ReadVersion reads YTSP-### and returns MAJOR and MINOR.
func ReadVersion(src []byte) (major, minor, n int, err error) {
	if len(src) < VersionSize {
		return 0, 0, 0, ErrTruncated
	}
	if src[0] != YTSP[0] || src[1] != YTSP[1] || src[2] != YTSP[2] {
		return 0, 0, 0, fmt.Errorf("%w: not a YTSP version code", ErrUnexpectedCode)
	}
	w := triplet(src[3:])
	if w>>18 != selDash {
		return 0, 0, 0, fmt.Errorf("%w: malformed version code", ErrUnexpectedCode)
	}
	return int((w >> 12) & 0x3F), int(w & 0xFFF), VersionSize, nil
}

// ---------------------------------------------------------------------------
// Text domain

// ToText transcodes a binary-domain (qb2) CESR stream to its text domain
// (qb64). The input must be a whole number of triplets.
func ToText(b []byte) (string, error) {
	if len(b)%3 != 0 {
		return "", fmt.Errorf("%w: binary stream of %d bytes is not triplet-aligned", ErrNonCanonical, len(b))
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FromText transcodes a text-domain (qb64) CESR stream to the binary domain.
// The input must be a whole number of quadlets.
func FromText(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("%w: text stream of %d characters is not quadlet-aligned", ErrNonCanonical, len(s))
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}
