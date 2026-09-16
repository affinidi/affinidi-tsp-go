package tsp

import (
	"crypto/subtle"
	"errors"

	tspcrypto "github.com/affinidi/affinidi-tsp-go/crypto"
)

// Message is an opened TSP message.
type Message struct {
	Version Version
	// Sender and Receiver are the envelope VIDs. Receiver is "" when the
	// envelope names the NULL VID.
	Sender, Receiver string
	// Scheme is how the payload was protected.
	Scheme Scheme
	// PayloadSender is the ESSR VID_sndr field inside the payload; "" for the
	// NULL VID. When present it has been checked against Sender.
	PayloadSender string
	// Padding is the content of the Padding_Field.
	Padding []byte
	// Payload is the decoded payload. A *HOP's Inner message is not opened.
	Payload Payload
}

// Envelope is what Peek reveals without keys: what an intermediary sees.
type Envelope struct {
	Version          Version
	Sender, Receiver string
	// Confidential reports whether the payload is encrypted.
	Confidential bool
	// SealedBox reports a sealed-box ciphertext (code C) rather than HPKE
	// (code F). Whether an HPKE message uses the post-quantum KEM is not
	// visible on the wire.
	SealedBox bool
}

// Peek parses a message's framing and returns its envelope. It checks that the
// message is structurally well formed (envelope, body and signature
// attachment, with no trailing bytes) but verifies nothing cryptographic.
func Peek(msg []byte) (*Envelope, error) {
	pm, err := parseMessage(msg)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Version:      pm.version,
		Sender:       pm.sender,
		Receiver:     pm.receiver,
		Confidential: pm.kind != bodyCleartext,
		SealedBox:    pm.kind == bodySealedBox,
	}, nil
}

// Open verifies and decrypts a message addressed to receiver from sender.
//
// It checks, in order: framing; that the envelope names receiver and sender;
// the signature, under sender's signing key; decryption, with the envelope as
// HPKE associated data; the payload framing; the ESSR sender field against the
// envelope; and any SAID the payload carries.
//
// receiver needs its decryption private key unless the message is signed-only.
func Open(receiver *PrivateIdentity, sender *Identity, msg []byte) (*Message, error) {
	if err := receiver.Validate(); err != nil {
		return nil, err
	}
	if err := sender.Validate(); err != nil {
		return nil, err
	}
	pm, err := parseMessage(msg)
	if err != nil {
		return nil, err
	}

	if pm.receiver == "" {
		if pm.kind != bodyCleartext {
			return nil, newErr(KindReceiver, "a confidential message must name its receiver")
		}
	} else if subtle.ConstantTimeCompare([]byte(pm.receiver), []byte(receiver.VID)) != 1 {
		return nil, newErr(KindReceiver, "message is addressed to %q, not %q", pm.receiver, receiver.VID)
	}
	if pm.sender != sender.VID {
		return nil, newErr(KindSender, "message is from %q, not %q", pm.sender, sender.VID)
	}

	if pm.signature.typ != sender.SigKeyType {
		return nil, newErr(KindSignature, "message signed with %v, but %s signs with %v", pm.signature.typ, sender.VID, sender.SigKeyType)
	}
	switch sender.SigKeyType {
	case SigKeyEd25519:
		err = tspcrypto.Ed25519Verify(sender.SigningKey, pm.signed, pm.signature.sig)
	case SigKeyMLDSA65:
		err = tspcrypto.MLDSA65Verify(sender.SigningKey, pm.signed, pm.signature.sig)
	}
	if err != nil {
		return nil, wrapErr(KindSignature, err, "sender signature")
	}

	var scheme Scheme
	var frame []byte
	switch pm.kind {
	case bodyCleartext:
		scheme, frame = SchemeSignedOnly, pm.body
	case bodyHPKE, bodySealedBox:
		if len(receiver.DecryptionPrivateKey) == 0 {
			return nil, newErr(KindInvalidInput, "%s: no decryption private key", receiver.VID)
		}
		switch {
		case pm.kind == bodySealedBox && receiver.EncKeyType == EncKeyX25519:
			scheme = SchemeSealedBox
			frame, err = tspcrypto.SealedBoxOpen(receiver.DecryptionPrivateKey, pm.body)
		case pm.kind == bodyHPKE && receiver.EncKeyType == EncKeyX25519:
			scheme = SchemeHPKEBase
			frame, err = tspcrypto.HPKEBaseOpen(receiver.DecryptionPrivateKey, hpkeInfo, pm.envFields, pm.body)
		case pm.kind == bodyHPKE && receiver.EncKeyType == EncKeyMLKEM768X25519:
			scheme = SchemeHPKEPQ
			frame, err = tspcrypto.HPKEPQOpen(receiver.DecryptionPrivateKey, hpkeInfo, pm.envFields, pm.body)
		default:
			return nil, newErr(KindDecrypt, "receiver's %v key cannot open this ciphertext", receiver.EncKeyType)
		}
		if err != nil {
			if errors.Is(err, tspcrypto.ErrKey) {
				return nil, wrapErr(KindInvalidInput, err, "decrypting payload")
			}
			return nil, wrapErr(KindDecrypt, err, "decrypting payload")
		}
	}

	dp, err := decodePayload(frame, pm.envFields)
	if err != nil {
		return nil, err
	}
	if dp.payloadSender != "" {
		if subtle.ConstantTimeCompare([]byte(dp.payloadSender), []byte(pm.sender)) != 1 {
			return nil, newErr(KindSender, "ESSR sender VID does not match the envelope sender")
		}
	} else if scheme == SchemeSealedBox {
		return nil, newErr(KindSender, "a sealed-box payload must carry the ESSR sender VID")
	}
	if _, ok := dp.payload.(*HOP); ok && scheme == SchemeSignedOnly {
		return nil, newErr(KindMalformed, "a nested or routed message must be confidential")
	}

	return &Message{
		Version:       pm.version,
		Sender:        pm.sender,
		Receiver:      pm.receiver,
		Scheme:        scheme,
		PayloadSender: dp.payloadSender,
		Padding:       dp.padding,
		Payload:       dp.payload,
	}, nil
}

// VerifyReferral checks the Signature_new of an invite that introduces a new
// VID (a Referral), against introduced, the resolved new VID.
//
// Open does not do this: the key of the introduced VID is exactly what the
// invite exists to convey, so it has to be resolved first. Until a caller
// verifies it, a referral is only the sender's claim.
func VerifyReferral(m *Message, introduced *Identity) error {
	if m == nil {
		return newErr(KindInvalidInput, "nil message")
	}
	rfi, ok := m.Payload.(*RFI)
	if !ok || rfi.Referral == nil {
		return newErr(KindInvalidInput, "message is not an invite carrying a referral")
	}
	if err := introduced.Validate(); err != nil {
		return err
	}
	if introduced.VID != rfi.Referral.VID {
		return newErr(KindSender, "referral introduces %q, not %q", rfi.Referral.VID, introduced.VID)
	}
	tag := payloadTags[PayloadRFI]
	signed := append([]byte(nil), tag[:]...)
	var err error
	if signed, err = appendVID(signed, m.PayloadSender); err != nil {
		return err
	}
	signed = appendDigest(signed, rfi.Digest)
	signed = appendNonce(signed, rfi.Nonce)
	if signed, err = appendVIDList(signed, rfi.ReplyPath); err != nil {
		return err
	}
	if signed, err = appendVID(signed, rfi.Referral.VID); err != nil {
		return err
	}
	switch introduced.SigKeyType {
	case SigKeyEd25519:
		err = tspcrypto.Ed25519Verify(introduced.SigningKey, signed, rfi.Referral.Signature)
	case SigKeyMLDSA65:
		err = tspcrypto.MLDSA65Verify(introduced.SigningKey, signed, rfi.Referral.Signature)
	}
	if err != nil {
		return wrapErr(KindSignature, err, "referral signature")
	}
	return nil
}
