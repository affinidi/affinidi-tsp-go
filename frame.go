package tsp

import (
	"errors"
	"unicode/utf8"

	"github.com/affinidi/affinidi-tsp-go/cesr"
	tspcrypto "github.com/affinidi/affinidi-tsp-go/crypto"
)

// Limits applied to untrusted input.
const (
	// MaxMessageSize bounds the size of a whole encoded message.
	MaxMessageSize = 64 << 20
	// MaxHops bounds a hop list or reply path.
	MaxHops = 64
)

// saidDummy fills a digest's own slot during SAID derivation: 0x23 over the
// full encoded width of a 256-bit digest primitive (code + 32 bytes).
var saidDummy = func() []byte {
	b := make([]byte, cesr.FixedSize(32))
	for i := range b {
		b[i] = 0x23
	}
	return b
}()

// hpkeInfo is the HPKE info parameter: the TSP protocol code "YTSP-" as five
// ASCII bytes.
var hpkeInfo = []byte("YTSP-")

func cesrErr(err error, what string) *Error {
	return wrapErr(KindMalformed, err, "%s", what)
}

// ---------------------------------------------------------------------------
// Field encoders

func appendVID(dst []byte, vid string) ([]byte, error) {
	if len(vid) > MaxVIDSize {
		return dst, newErr(KindInvalidInput, "VID of %d bytes exceeds %d", len(vid), MaxVIDSize)
	}
	out, err := cesr.AppendVarData(dst, cesr.CodeB, []byte(vid))
	if err != nil {
		return dst, wrapErr(KindInvalidInput, err, "encoding VID")
	}
	return out, nil
}

func appendVIDList(dst []byte, vids []string) ([]byte, error) {
	if len(vids) > MaxHops {
		return dst, newErr(KindInvalidInput, "%d VIDs in a list, at most %d", len(vids), MaxHops)
	}
	var body []byte
	for _, v := range vids {
		if err := validateVID(v); err != nil {
			return dst, err
		}
		var err error
		if body, err = appendVID(body, v); err != nil {
			return dst, err
		}
	}
	out, err := cesr.AppendCount(dst, cesr.CodeJ, len(body)/3)
	if err != nil {
		return dst, wrapErr(KindInvalidInput, err, "encoding VID list")
	}
	return append(out, body...), nil
}

func appendDigest(dst []byte, d Digest) []byte {
	out, _ := cesr.AppendFixed(dst, d.Alg.code(), d.Value[:]) // cannot fail for 32 bytes
	return out
}

func appendNonce(dst []byte, nonce []byte) []byte {
	out, _ := cesr.AppendFixed(dst, uint32(cesr.CodeA), nonce) // cannot fail for 16 bytes
	return out
}

// appendSignatureAttachment appends -C## -K## followed by one signature: an
// indexed Ed25519 signature (index 0) or an ML-DSA-65 signature (1AAQ),
// selected by length.
func appendSignatureAttachment(dst []byte, sig []byte) ([]byte, error) {
	var prim []byte
	var err error
	switch len(sig) {
	case tspcrypto.Ed25519SignatureSize:
		prim, err = cesr.AppendIndexedEd25519(nil, 0, sig)
	case tspcrypto.MLDSA65SignatureSize:
		prim, err = cesr.AppendFixed(nil, cesr.CodeMLDSA65, sig)
	default:
		return dst, newErr(KindInvalidInput, "signature of %d bytes is neither Ed25519 nor ML-DSA-65", len(sig))
	}
	if err != nil {
		return dst, wrapErr(KindInternal, err, "encoding signature")
	}
	q := len(prim) / 3
	dst, _ = cesr.AppendCount(dst, cesr.CodeC, q+1)
	dst, _ = cesr.AppendCount(dst, cesr.CodeK, q)
	return append(dst, prim...), nil
}

// appendStream appends a -A## generic stream holding data as a single Bytes
// primitive.
func appendStream(dst, data []byte) ([]byte, error) {
	prim, err := cesr.AppendVarData(nil, cesr.CodeB, data)
	if err != nil {
		return dst, wrapErr(KindInvalidInput, err, "encoding payload data")
	}
	out, err := cesr.AppendCount(dst, cesr.CodeA, len(prim)/3)
	if err != nil {
		return dst, wrapErr(KindInvalidInput, err, "encoding payload stream")
	}
	return append(out, prim...), nil
}

// ---------------------------------------------------------------------------
// Payload frame encoding

// frameInput carries what the payload encoder needs beyond the payload.
type frameInput struct {
	envFields    []byte // TSP_Version || VID_sndr || VID_rcvr, the SAID prefix
	senderField  []byte // encoded ESSR VID_sndr (or 4BAA)
	padding      []byte
	digestAlg    DigestAlg // resolved (never DigestDefault)
	nonce        func() ([]byte, error)
	signReferral func(msg []byte) ([]byte, error)
}

// encodePayload builds the plaintext payload frame -Z## ... and returns it
// with the SAID the payload carries (RFI Digest, RFA Reply_Digest), if any.
//
// Every layout is: type code, ESSR sender, type-specific fields, with the
// padding field at the position the layout gives it. The SAID excludes the
// -E/-Z framing and the padding field, so it is computed from the pieces
// before and after the padding.
func encodePayload(p Payload, in *frameInput) (frame []byte, said *Digest, err error) {
	var tag [3]byte
	var ok bool
	if p == nil {
		return nil, nil, newErr(KindInvalidInput, "nil payload")
	}
	if tag, ok = payloadTags[p.Type()]; !ok {
		return nil, nil, newErr(KindUnsupported, "payload type %v", p.Type())
	}
	pre := append(tag[:], in.senderField...) // fields before the padding
	var post []byte                          // fields after the padding

	switch p := p.(type) {
	case *SCS:
		if post, err = appendStream(nil, p.Data); err != nil {
			return nil, nil, err
		}
	case *CTL:
		if post, err = appendStream(nil, p.Data); err != nil {
			return nil, nil, err
		}
	case *PAD:
		nonce, err := resolveNonce(p.Nonce, in.nonce)
		if err != nil {
			return nil, nil, err
		}
		pre = appendNonce(pre, nonce)
	case *HOP:
		if len(p.Inner)%3 != 0 {
			return nil, nil, newErr(KindInvalidInput, "inner message is not triplet-aligned")
		}
		if _, err := parseMessage(p.Inner); err != nil {
			return nil, nil, wrapErr(KindInvalidInput, err, "inner message")
		}
		if pre, err = appendVIDList(pre, p.Hops); err != nil {
			return nil, nil, err
		}
		post = p.Inner
	case *RFI:
		nonce, err := resolveNonce(p.Nonce, in.nonce)
		if err != nil {
			return nil, nil, err
		}
		var tail []byte // nonce || reply path
		tail = appendNonce(tail, nonce)
		if tail, err = appendVIDList(tail, p.ReplyPath); err != nil {
			return nil, nil, err
		}
		// The SAID covers a bare VID_new field for a referral, not the -J group
		// around it, and never Signature_new; an absent referral contributes -JAA.
		var referralInput []byte
		if p.Referral != nil {
			if err := validateVID(p.Referral.VID); err != nil {
				return nil, nil, err
			}
			if referralInput, err = appendVID(nil, p.Referral.VID); err != nil {
				return nil, nil, err
			}
		} else {
			referralInput, _ = cesr.AppendCount(nil, cesr.CodeJ, 0)
		}
		d := computeSAID(in.digestAlg, in.envFields, pre, nil, tail, referralInput)
		digestField := appendDigest(nil, d)

		pre = append(pre, digestField...)
		pre = append(pre, tail...)
		if p.Referral == nil {
			pre = append(pre, referralInput...)
		} else {
			sig := p.Referral.Signature
			if sig == nil {
				if in.signReferral == nil {
					return nil, nil, newErr(KindInvalidInput, "referral has no signature and no referral signer was given")
				}
				// Signature_new covers {XRFI, VID_sndr, Digest, Nonce, Reply_Path, VID_new}.
				signed := append(append(append([]byte(nil), tag[:]...), in.senderField...), digestField...)
				signed = append(signed, tail...)
				signed = append(signed, referralInput...)
				if sig, err = in.signReferral(signed); err != nil {
					return nil, nil, err
				}
			}
			group := append([]byte(nil), referralInput...)
			if group, err = appendSignatureAttachment(group, sig); err != nil {
				return nil, nil, err
			}
			pre, _ = cesr.AppendCount(pre, cesr.CodeJ, len(group)/3)
			pre = append(pre, group...)
		}
		said = &d
	case *RFA:
		inv := p.InviteDigest
		if inv.Alg == DigestDefault {
			return nil, nil, newErr(KindInvalidInput, "accept must name the invite digest's algorithm")
		}
		pre = appendDigest(pre, inv)
		d := computeSAID(in.digestAlg, in.envFields, pre, saidDummy)
		pre = appendDigest(pre, d)
		said = &d
	case *RFD:
		d := p.Digest
		if d.Alg == DigestDefault {
			d.Alg = DigestSHA2256
		}
		pre = appendDigest(pre, d)
	default:
		return nil, nil, newErr(KindUnsupported, "payload type %T", p)
	}

	pad, err := cesr.AppendVarData(nil, cesr.CodeB, in.padding)
	if err != nil {
		return nil, nil, wrapErr(KindInvalidInput, err, "encoding padding")
	}
	bodyLen := len(pre) + len(pad) + len(post)
	if bodyLen%3 != 0 {
		return nil, nil, newErr(KindInternal, "payload frame is not triplet-aligned")
	}
	frame = make([]byte, 0, cesr.CountSize(bodyLen/3)+bodyLen)
	if frame, err = cesr.AppendCount(frame, cesr.CodeZ, bodyLen/3); err != nil {
		return nil, nil, wrapErr(KindInvalidInput, err, "payload too large")
	}
	frame = append(frame, pre...)
	frame = append(frame, pad...)
	frame = append(frame, post...)
	return frame, said, nil
}

// computeSAID hashes envFields followed by parts. For an RFI the caller passes
// the fields up to the digest slot, nil (meaning: insert the dummy), then the
// fields after; for an RFA the dummy is passed explicitly as the last part.
func computeSAID(alg DigestAlg, envFields []byte, parts ...[]byte) Digest {
	n := len(envFields)
	for _, p := range parts {
		if p == nil {
			n += len(saidDummy)
		}
		n += len(p)
	}
	in := make([]byte, 0, n)
	in = append(in, envFields...)
	for _, p := range parts {
		if p == nil {
			in = append(in, saidDummy...)
			continue
		}
		in = append(in, p...)
	}
	d := Digest{Alg: alg}
	if alg == DigestBlake2b256 {
		d.Value = tspcrypto.Blake2b256(in)
	} else {
		d.Alg = DigestSHA2256
		d.Value = tspcrypto.SHA256(in)
	}
	return d
}

func resolveNonce(nonce []byte, gen func() ([]byte, error)) ([]byte, error) {
	if nonce == nil {
		return gen()
	}
	if len(nonce) != NonceSize {
		return nil, newErr(KindInvalidInput, "nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	return nonce, nil
}

// ---------------------------------------------------------------------------
// Payload frame decoding

// decodedPayload is a parsed payload frame.
type decodedPayload struct {
	payload       Payload
	payloadSender string // "" for the NULL VID
	padding       []byte
}

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) rest() []byte { return c.b[c.pos:] }

func (c *cursor) varData(code byte, what string) ([]byte, error) {
	d, n, err := cesr.ReadVarData(c.rest(), code)
	if err != nil {
		return nil, cesrErr(err, what)
	}
	c.pos += n
	return d, nil
}

func (c *cursor) count(code byte, what string) (int, error) {
	v, n, err := cesr.ReadCount(c.rest(), code)
	if err != nil {
		return 0, cesrErr(err, what)
	}
	c.pos += n
	return v, nil
}

func (c *cursor) vid(what string) (string, error) {
	d, err := c.varData(cesr.CodeB, what)
	if err != nil {
		return "", err
	}
	if len(d) > MaxVIDSize {
		return "", newErr(KindMalformed, "%s of %d bytes exceeds %d", what, len(d), MaxVIDSize)
	}
	if !utf8.Valid(d) {
		return "", newErr(KindMalformed, "%s is not valid UTF-8", what)
	}
	return string(d), nil
}

// vidList reads a -J## group of VIDs whose count is its byte length.
func (c *cursor) vidList(what string) ([]string, error) {
	q, err := c.count(cesr.CodeJ, what)
	if err != nil {
		return nil, err
	}
	end := c.pos + q*3
	if q > len(c.b) || end > len(c.b) {
		return nil, newErr(KindMalformed, "%s overruns the payload", what)
	}
	sub := &cursor{b: c.b[:end], pos: c.pos}
	var vids []string
	for sub.pos < end {
		if len(vids) == MaxHops {
			return nil, newErr(KindMalformed, "%s has more than %d VIDs", what, MaxHops)
		}
		v, err := sub.vid(what)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, newErr(KindMalformed, "%s contains the NULL VID", what)
		}
		vids = append(vids, v)
	}
	c.pos = end
	if vids == nil {
		vids = []string{}
	}
	return vids, nil
}

func (c *cursor) digest(what string) (Digest, []byte, error) {
	start := c.pos
	for _, alg := range []DigestAlg{DigestSHA2256, DigestBlake2b256} {
		v, n, err := cesr.ReadFixed(c.rest(), alg.code(), 32)
		if err == nil {
			d := Digest{Alg: alg}
			copy(d.Value[:], v)
			c.pos += n
			return d, c.b[start:c.pos], nil
		}
		if errors.Is(err, cesr.ErrTruncated) {
			return Digest{}, nil, cesrErr(err, what)
		}
	}
	return Digest{}, nil, newErr(KindMalformed, "%s is not a SHA2-256 or Blake2b-256 digest", what)
}

func (c *cursor) nonce(what string) ([]byte, error) {
	v, n, err := cesr.ReadFixed(c.rest(), uint32(cesr.CodeA), NonceSize)
	if err != nil {
		return nil, cesrErr(err, what)
	}
	c.pos += n
	return append([]byte(nil), v...), nil
}

// stream reads a -A## generic stream that must end exactly at the end of b.
func (c *cursor) stream() ([]byte, error) {
	q, err := c.count(cesr.CodeA, "payload stream")
	if err != nil {
		return nil, err
	}
	if q*3 != len(c.b)-c.pos {
		return nil, newErr(KindMalformed, "payload stream count does not match the payload frame")
	}
	// The stream is exactly one Bytes primitive and nothing else: the form the
	// specification's vectors and the ToIP reference use (spec issue #77).
	d, n, err := cesr.ReadVarData(c.rest(), cesr.CodeB)
	if err != nil {
		return nil, cesrErr(err, "payload data")
	}
	if n != len(c.rest()) {
		return nil, newErr(KindMalformed, "payload stream holds more than one Bytes primitive")
	}
	c.pos = len(c.b)
	return append([]byte{}, d...), nil
}

// decodePayload parses a plaintext payload frame. envFields is the message's
// TSP_Version || VID_sndr || VID_rcvr as received, used to verify SAIDs.
func decodePayload(frame, envFields []byte) (*decodedPayload, error) {
	c := &cursor{b: frame}
	q, err := c.count(cesr.CodeZ, "payload frame")
	if err != nil {
		return nil, err
	}
	if q*3 != len(frame)-c.pos {
		return nil, newErr(KindMalformed, "payload frame count %d does not match its %d bytes", q, len(frame)-c.pos)
	}
	body := c.pos
	if len(frame)-c.pos < 3 {
		return nil, newErr(KindMalformed, "truncated payload type")
	}
	var tag [3]byte
	copy(tag[:], c.rest())
	c.pos += 3
	var typ PayloadType
	for t, v := range payloadTags {
		if v == tag {
			typ = t
		}
	}
	if typ == 0 {
		return nil, newErr(KindUnsupported, "unknown payload type code %x", tag)
	}

	senderStart := c.pos
	sender, err := c.vid("ESSR sender VID")
	if err != nil {
		return nil, err
	}
	senderField := frame[senderStart:c.pos]
	out := &decodedPayload{payloadSender: sender}

	readPadding := func() error {
		pad, err := c.varData(cesr.CodeB, "padding field")
		if err != nil {
			return err
		}
		out.padding = append([]byte{}, pad...)
		return nil
	}

	switch typ {
	case PayloadSCS, PayloadCTL:
		if err := readPadding(); err != nil {
			return nil, err
		}
		data, err := c.stream()
		if err != nil {
			return nil, err
		}
		if typ == PayloadSCS {
			out.payload = &SCS{Data: data}
		} else {
			out.payload = &CTL{Data: data}
		}
	case PayloadPAD:
		nonce, err := c.nonce("nonce")
		if err != nil {
			return nil, err
		}
		if err := readPadding(); err != nil {
			return nil, err
		}
		out.payload = &PAD{Nonce: nonce}
	case PayloadHOP:
		hops, err := c.vidList("hop list")
		if err != nil {
			return nil, err
		}
		if err := readPadding(); err != nil {
			return nil, err
		}
		inner := c.rest()
		if _, err := parseMessage(inner); err != nil {
			return nil, wrapErr(KindMalformed, err, "inner message")
		}
		c.pos = len(frame)
		out.payload = &HOP{Hops: hops, Inner: append([]byte(nil), inner...)}
	case PayloadRFI:
		digest, _, err := c.digest("invite digest")
		if err != nil {
			return nil, err
		}
		tailStart := c.pos
		nonce, err := c.nonce("nonce")
		if err != nil {
			return nil, err
		}
		replyPath, err := c.vidList("reply path")
		if err != nil {
			return nil, err
		}
		tail := frame[tailStart:c.pos]

		refStart := c.pos
		rq, err := c.count(cesr.CodeJ, "referral field")
		if err != nil {
			return nil, err
		}
		var referralInput []byte
		rfi := &RFI{Nonce: nonce, ReplyPath: replyPath}
		if rq == 0 {
			referralInput = frame[refStart:c.pos]
		} else {
			end := c.pos + rq*3
			if rq > len(frame) || end > len(frame) {
				return nil, newErr(KindMalformed, "referral field overruns the payload")
			}
			sub := &cursor{b: frame[:end], pos: c.pos}
			vidStart := sub.pos
			vid, err := sub.vid("referral VID")
			if err != nil {
				return nil, err
			}
			if vid == "" {
				return nil, newErr(KindMalformed, "referral names the NULL VID")
			}
			referralInput = frame[vidStart:sub.pos]
			sig, n, err := readSignatureAttachment(sub.rest())
			if err != nil {
				return nil, err
			}
			if sub.pos+n != end {
				return nil, newErr(KindMalformed, "referral field does not fill its count")
			}
			c.pos = end
			rfi.Referral = &Referral{VID: vid, Signature: append([]byte(nil), sig.sig...)}
		}
		want := computeSAID(digest.Alg, envFields, frame[body:body+3], senderField, nil, tail, referralInput)
		if !want.Equal(digest) {
			return nil, newErr(KindDigest, "invite digest does not match the message")
		}
		rfi.Digest = digest
		if err := readPadding(); err != nil {
			return nil, err
		}
		out.payload = rfi
	case PayloadRFA:
		invite, inviteField, err := c.digest("invite digest")
		if err != nil {
			return nil, err
		}
		reply, _, err := c.digest("reply digest")
		if err != nil {
			return nil, err
		}
		want := computeSAID(reply.Alg, envFields, frame[body:body+3], senderField, inviteField, saidDummy)
		if !want.Equal(reply) {
			return nil, newErr(KindDigest, "reply digest does not match the message")
		}
		if err := readPadding(); err != nil {
			return nil, err
		}
		out.payload = &RFA{InviteDigest: invite, ReplyDigest: reply}
	case PayloadRFD:
		d, _, err := c.digest("digest")
		if err != nil {
			return nil, err
		}
		if err := readPadding(); err != nil {
			return nil, err
		}
		out.payload = &RFD{Digest: d}
	}
	if c.pos != len(frame) {
		return nil, newErr(KindMalformed, "%d trailing bytes in the payload frame", len(frame)-c.pos)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Message (envelope + body + signature) parsing

type bodyKind uint8

const (
	bodyCleartext bodyKind = iota
	bodyHPKE               // code F
	bodySealedBox          // code C
)

type parsedSignature struct {
	typ SigKeyType
	sig []byte
}

// parsedMessage is a structurally valid TSP message whose cryptography has not
// been checked.
type parsedMessage struct {
	version   Version
	sender    string
	receiver  string // "" for the NULL VID
	envFields []byte // TSP_Version || VID_sndr || VID_rcvr (the HPKE aad)
	signed    []byte // the -E frame: everything the signature covers
	kind      bodyKind
	body      []byte // ciphertext, or the cleartext -Z frame
	signature parsedSignature
}

// parseMessage checks the framing of a complete message: the -E frame and its
// count, the version, both VIDs, the body, and one signature attachment
// filling the rest of the input exactly.
func parseMessage(msg []byte) (*parsedMessage, error) {
	if len(msg) > MaxMessageSize {
		return nil, newErr(KindMalformed, "message of %d bytes exceeds %d", len(msg), MaxMessageSize)
	}
	c := &cursor{b: msg}
	q, err := c.count(cesr.CodeE, "TSP envelope")
	if err != nil {
		return nil, err
	}
	contentStart := c.pos
	if q > len(msg) || contentStart+q*3 > len(msg) {
		return nil, newErr(KindMalformed, "envelope count exceeds the message")
	}
	contentEnd := contentStart + q*3
	c.b = msg[:contentEnd] // envelope fields and body may not run past the -E count

	major, minor, n, err := cesr.ReadVersion(c.rest())
	if err != nil {
		return nil, cesrErr(err, "TSP version")
	}
	c.pos += n
	if major != CurrentVersion.Major {
		return nil, newErr(KindVersion, "unsupported TSP version %s (%s); this package speaks TSP 1.0", Version{major, minor}, describeVersion(major, minor))
	}
	sender, err := c.vid("sender VID")
	if err != nil {
		return nil, err
	}
	if sender == "" {
		return nil, newErr(KindMalformed, "envelope sender is the NULL VID")
	}
	receiver, err := c.vid("receiver VID")
	if err != nil {
		return nil, err
	}
	pm := &parsedMessage{
		version:   Version{Major: major, Minor: minor},
		sender:    sender,
		receiver:  receiver,
		envFields: msg[contentStart:c.pos],
		signed:    msg[:contentEnd],
	}

	switch rest := c.rest(); {
	case cesr.PeekVarDataCode(rest, cesr.CodeF):
		pm.kind = bodyHPKE
	case cesr.PeekVarDataCode(rest, cesr.CodeC):
		pm.kind = bodySealedBox
	default:
		pm.kind = bodyCleartext
	}
	if pm.kind == bodyCleartext {
		body := c.rest()
		zq, n, err := cesr.ReadCount(body, cesr.CodeZ)
		if err != nil {
			return nil, cesrErr(err, "payload")
		}
		if zq*3 != len(body)-n {
			return nil, newErr(KindMalformed, "payload count does not fill the envelope")
		}
		pm.body = body
	} else {
		code := cesr.CodeF
		if pm.kind == bodySealedBox {
			code = cesr.CodeC
		}
		ct, err := c.varData(code, "ciphertext")
		if err != nil {
			return nil, err
		}
		if c.pos != contentEnd {
			return nil, newErr(KindMalformed, "ciphertext does not fill the envelope")
		}
		pm.body = ct
	}

	sig, n, err := readSignatureAttachment(msg[contentEnd:])
	if err != nil {
		return nil, err
	}
	if contentEnd+n != len(msg) {
		return nil, newErr(KindMalformed, "%d trailing bytes after the signature", len(msg)-contentEnd-n)
	}
	pm.signature = sig
	return pm, nil
}

// readSignatureAttachment reads -C## -K## and exactly one signature filling
// both groups.
func readSignatureAttachment(src []byte) (parsedSignature, int, error) {
	c := &cursor{b: src}
	cq, err := c.count(cesr.CodeC, "signature attachment")
	if err != nil {
		return parsedSignature{}, 0, err
	}
	if cq > len(src) || c.pos+cq*3 > len(src) {
		return parsedSignature{}, 0, newErr(KindMalformed, "signature attachment overruns the message")
	}
	end := c.pos + cq*3
	c.b = src[:end]
	kq, err := c.count(cesr.CodeK, "indexed signature group")
	if err != nil {
		return parsedSignature{}, 0, err
	}
	if c.pos+kq*3 != end {
		return parsedSignature{}, 0, newErr(KindMalformed, "indexed signature group does not fill the attachment")
	}
	rest := c.rest()
	if idx, sig, n, err := cesr.ReadIndexedEd25519(rest); err == nil {
		if n != len(rest) {
			return parsedSignature{}, 0, newErr(KindMalformed, "signature group holds more than one signature")
		}
		if idx != 0 {
			return parsedSignature{}, 0, newErr(KindUnsupported, "signature key index %d (single-key VIDs only)", idx)
		}
		return parsedSignature{typ: SigKeyEd25519, sig: sig}, end, nil
	} else if !errors.Is(err, cesr.ErrUnexpectedCode) {
		return parsedSignature{}, 0, cesrErr(err, "Ed25519 signature")
	}
	sig, n, err := cesr.ReadFixed(rest, cesr.CodeMLDSA65, tspcrypto.MLDSA65SignatureSize)
	if err != nil {
		return parsedSignature{}, 0, cesrErr(err, "signature (neither Ed25519 nor ML-DSA-65)")
	}
	if n != len(rest) {
		return parsedSignature{}, 0, newErr(KindMalformed, "signature group holds more than one signature")
	}
	return parsedSignature{typ: SigKeyMLDSA65, sig: sig}, end, nil
}
