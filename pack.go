package tsp

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/affinidi/affinidi-tsp-go/cesr"
	tspcrypto "github.com/affinidi/affinidi-tsp-go/crypto"
)

// SenderField selects what a payload carries in its ESSR VID_sndr field.
type SenderField uint8

// ESSR sender field choices.
const (
	// SenderFieldDefault is the scheme's default: the sender's VID under the
	// sealed box (which requires it), the NULL VID otherwise.
	SenderFieldDefault SenderField = iota
	// SenderFieldNull carries the NULL VID 4BAA. Not permitted under the sealed
	// box.
	SenderFieldNull
	// SenderFieldPresent carries the envelope sender's VID.
	SenderFieldPresent
)

// PackOptions tunes Pack. The zero value is valid.
type PackOptions struct {
	// Scheme selects the payload protection. SchemeAuto picks HPKE by the
	// receiver's encryption key type.
	Scheme Scheme
	// Padding is the content of the payload's Padding_Field. The receiver
	// discards it; it exists to hide the payload's size.
	Padding []byte
	// PayloadSender selects the ESSR sender field.
	PayloadSender SenderField
	// DigestAlg is the algorithm of the SAID an RFI or RFA carries.
	// DigestDefault uses Blake2b-256 under the sealed box, SHA2-256 otherwise.
	DigestAlg DigestAlg
	// ReferralSigner is the introduced VID, used to produce Signature_new when
	// an RFI carries a Referral without a Signature.
	ReferralSigner *PrivateIdentity
	// Rand is the source of nonces, ephemeral keys and signature randomness.
	// Defaults to crypto/rand.
	Rand io.Reader
	// Ephemeral pins the encryption's ephemeral key material, making the
	// output reproducible: the HPKE DeriveKeyPair input ikmE under HPKE-Base,
	// the ephemeral X25519 secret under the sealed box. It exists to reproduce
	// published test vectors. Never set it otherwise: reusing ephemeral key
	// material destroys confidentiality. Not supported for HPKE-PQ.
	Ephemeral []byte
}

// Packed is an encoded TSP message.
type Packed struct {
	// Message is the binary-domain (qb2) wire encoding.
	Message []byte
	// Digest is the SAID the message carries: an RFI's Digest or an RFA's
	// Reply_Digest. Nil for other payload types.
	Digest *Digest
}

// Pack encodes, protects and signs a TSP message from sender to receiver.
//
// sender must hold its signing private key. receiver supplies the encryption
// key for a confidential scheme; it may be nil for a signed-only message, in
// which case the envelope names the NULL VID as receiver.
func Pack(sender *PrivateIdentity, receiver *Identity, payload Payload, opts *PackOptions) (*Packed, error) {
	if opts == nil {
		opts = &PackOptions{}
	}
	if err := sender.Validate(); err != nil {
		return nil, err
	}
	if len(sender.SigningPrivateKey) == 0 {
		return nil, newErr(KindInvalidInput, "%s: no signing private key", sender.VID)
	}
	rng := opts.Rand
	if rng == nil {
		rng = rand.Reader
	}

	scheme := opts.Scheme
	receiverVID := ""
	if receiver != nil {
		if err := receiver.Validate(); err != nil {
			return nil, err
		}
		receiverVID = receiver.VID
	}
	if scheme == SchemeAuto {
		if receiver == nil {
			return nil, newErr(KindInvalidInput, "a confidential message needs a receiver")
		}
		switch receiver.EncKeyType {
		case EncKeyX25519:
			scheme = SchemeHPKEBase
		case EncKeyMLKEM768X25519:
			scheme = SchemeHPKEPQ
		default:
			return nil, newErr(KindInvalidInput, "%s has no encryption key", receiver.VID)
		}
	}
	switch scheme {
	case SchemeHPKEBase, SchemeSealedBox:
		if receiver == nil || receiver.EncKeyType != EncKeyX25519 {
			return nil, newErr(KindInvalidInput, "%v needs a receiver with an X25519 encryption key", scheme)
		}
	case SchemeHPKEPQ:
		if receiver == nil || receiver.EncKeyType != EncKeyMLKEM768X25519 {
			return nil, newErr(KindInvalidInput, "%v needs a receiver with an MLKEM768-X25519 encryption key", scheme)
		}
		if opts.Ephemeral != nil {
			return nil, newErr(KindUnsupported, "HPKE-PQ encapsulation cannot be made deterministic")
		}
	case SchemeSignedOnly:
		if _, ok := payload.(*HOP); ok {
			return nil, newErr(KindInvalidInput, "a nested or routed message must be confidential")
		}
	default:
		return nil, newErr(KindUnsupported, "scheme %v", scheme)
	}

	var senderFieldVID string
	switch opts.PayloadSender {
	case SenderFieldDefault:
		if scheme == SchemeSealedBox {
			senderFieldVID = sender.VID
		}
	case SenderFieldNull:
		if scheme == SchemeSealedBox {
			return nil, newErr(KindInvalidInput, "the sealed box requires the ESSR sender VID in the payload")
		}
	case SenderFieldPresent:
		senderFieldVID = sender.VID
	default:
		return nil, newErr(KindInvalidInput, "payload sender option %d", opts.PayloadSender)
	}

	alg := opts.DigestAlg
	if alg == DigestDefault {
		alg = DigestSHA2256
		if scheme == SchemeSealedBox {
			alg = DigestBlake2b256
		}
	}
	if alg != DigestSHA2256 && alg != DigestBlake2b256 {
		return nil, newErr(KindInvalidInput, "digest algorithm %d", alg)
	}

	env, err := cesr.AppendVersion(nil, CurrentVersion.Major, CurrentVersion.Minor)
	if err != nil {
		return nil, wrapErr(KindInternal, err, "encoding version")
	}
	if env, err = appendVID(env, sender.VID); err != nil {
		return nil, err
	}
	if env, err = appendVID(env, receiverVID); err != nil {
		return nil, err
	}
	senderField, err := appendVID(nil, senderFieldVID)
	if err != nil {
		return nil, err
	}

	in := &frameInput{
		envFields:   env,
		senderField: senderField,
		padding:     opts.Padding,
		digestAlg:   alg,
		nonce: func() ([]byte, error) {
			n := make([]byte, NonceSize)
			if _, err := io.ReadFull(rng, n); err != nil {
				return nil, wrapErr(KindInternal, err, "reading randomness")
			}
			return n, nil
		},
	}
	if rs := opts.ReferralSigner; rs != nil {
		in.signReferral = func(msg []byte) ([]byte, error) {
			if rfi, ok := payload.(*RFI); ok && rfi.Referral != nil && rfi.Referral.VID != rs.VID {
				return nil, newErr(KindInvalidInput, "referral signer %s does not match referral VID %s", rs.VID, rfi.Referral.VID)
			}
			return sign(rs, msg, rng)
		}
	}
	frame, said, err := encodePayload(payload, in)
	if err != nil {
		return nil, err
	}

	var body []byte
	switch scheme {
	case SchemeSignedOnly:
		body = frame
	default:
		var ct []byte
		var code byte = cesr.CodeF
		switch scheme {
		case SchemeHPKEBase:
			ct, err = tspcrypto.HPKEBaseSeal(receiver.EncryptionKey, hpkeInfo, env, frame, opts.Ephemeral, rng)
		case SchemeHPKEPQ:
			ct, err = tspcrypto.HPKEPQSeal(receiver.EncryptionKey, hpkeInfo, env, frame)
		case SchemeSealedBox:
			code = cesr.CodeC
			ct, err = tspcrypto.SealedBoxSeal(receiver.EncryptionKey, frame, opts.Ephemeral, rng)
		}
		if err != nil {
			if errors.Is(err, tspcrypto.ErrKey) {
				return nil, wrapErr(KindInvalidInput, err, "encrypting payload")
			}
			return nil, wrapErr(KindInternal, err, "encrypting payload")
		}
		if body, err = cesr.AppendVarData(nil, code, ct); err != nil {
			return nil, wrapErr(KindInvalidInput, err, "payload too large")
		}
	}

	contentLen := len(env) + len(body)
	msg := make([]byte, 0, 6+contentLen+3312+6)
	if msg, err = cesr.AppendCount(msg, cesr.CodeE, contentLen/3); err != nil {
		return nil, wrapErr(KindInvalidInput, err, "message too large")
	}
	msg = append(msg, env...)
	msg = append(msg, body...)
	sig, err := sign(sender, msg, rng)
	if err != nil {
		return nil, err
	}
	if msg, err = appendSignatureAttachment(msg, sig); err != nil {
		return nil, err
	}
	if len(msg) > MaxMessageSize {
		return nil, newErr(KindInvalidInput, "message of %d bytes exceeds %d", len(msg), MaxMessageSize)
	}
	return &Packed{Message: msg, Digest: said}, nil
}

func sign(id *PrivateIdentity, msg []byte, rng io.Reader) ([]byte, error) {
	if len(id.SigningPrivateKey) == 0 {
		return nil, newErr(KindInvalidInput, "%s: no signing private key", id.VID)
	}
	var sig []byte
	var err error
	switch id.SigKeyType {
	case SigKeyEd25519:
		sig, err = tspcrypto.Ed25519Sign(id.SigningPrivateKey, msg)
	case SigKeyMLDSA65:
		sig, err = tspcrypto.MLDSA65Sign(id.SigningPrivateKey, msg, rng)
	default:
		return nil, newErr(KindUnsupported, "signature key type %v", id.SigKeyType)
	}
	if err != nil {
		return nil, wrapErr(KindInvalidInput, err, "signing")
	}
	return sig, nil
}
