// Package crypto holds the cryptographic primitives TSP Rev 3 composes:
// HPKE-Base over DHKEM(X25519, HKDF-SHA256) with ChaCha20Poly1305, the same
// suite over the MLKEM768-X25519 hybrid KEM, the libsodium anonymous sealed
// box, Ed25519 and ML-DSA-65 signatures, and the SHA2-256 / Blake2b-256
// digests.
//
// The X25519 HPKE suite is implemented here (RFC 9180 §4, §5.1, §7.1.3) so
// that encapsulation can be driven from a caller-supplied ikmE, which is what
// the TSP specification's Appendix A vectors publish. The hybrid KEM uses the
// standard library's crypto/hpke.
package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Errors reported by the PKAE schemes.
var (
	// ErrDecrypt reports that a ciphertext did not authenticate under the key
	// and associated data it was opened with.
	ErrDecrypt = errors.New("tsp/crypto: decryption failed")
	// ErrKey reports a malformed key.
	ErrKey = errors.New("tsp/crypto: invalid key")
)

// HPKE suite identifiers used by TSP.
const (
	KEMX25519HKDFSHA256  uint16 = 0x0020
	KEMMLKEM768X25519    uint16 = 0x647a
	KDFHKDFSHA256        uint16 = 0x0001
	AEADChaCha20Poly1305 uint16 = 0x0003
)

// Sizes of the HPKE suites.
const (
	X25519KeySize       = 32
	HPKEBaseEncSize     = 32
	HPKEPQEncSize       = 1120
	HPKEPQPublicKeySize = 1216
	HPKEPQSeedSize      = 32
	AEADTagSize         = chacha20poly1305.Overhead
)

var (
	kemSuiteID  = []byte{'K', 'E', 'M', byte(KEMX25519HKDFSHA256 >> 8), byte(KEMX25519HKDFSHA256)}
	hpkeSuiteID = func() []byte {
		b := []byte("HPKE")
		b = binary.BigEndian.AppendUint16(b, KEMX25519HKDFSHA256)
		b = binary.BigEndian.AppendUint16(b, KDFHKDFSHA256)
		return binary.BigEndian.AppendUint16(b, AEADChaCha20Poly1305)
	}()
)

func labeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	in := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	in = append(in, "HPKE-v1"...)
	in = append(in, suiteID...)
	in = append(in, label...)
	in = append(in, ikm...)
	return hkdf.Extract(sha256.New, in, salt)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	in := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	in = binary.BigEndian.AppendUint16(in, uint16(length))
	in = append(in, "HPKE-v1"...)
	in = append(in, suiteID...)
	in = append(in, label...)
	in = append(in, info...)
	return hkdf.Expand(sha256.New, prk, string(in), length)
}

// X25519DeriveKeyPair is DeriveKeyPair for DHKEM(X25519, HKDF-SHA256)
// (RFC 9180 §7.1.3). ikm must be at least 32 bytes.
func X25519DeriveKeyPair(ikm []byte) (*ecdh.PrivateKey, error) {
	if len(ikm) < X25519KeySize {
		return nil, fmt.Errorf("%w: DeriveKeyPair input of %d bytes, need at least 32", ErrKey, len(ikm))
	}
	prk, err := labeledExtract(kemSuiteID, nil, "dkp_prk", ikm)
	if err != nil {
		return nil, err
	}
	sk, err := labeledExpand(kemSuiteID, prk, "sk", nil, X25519KeySize)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(sk)
}

// X25519PublicKey returns the public key of a raw X25519 private key.
func X25519PublicKey(sk []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return k.PublicKey().Bytes(), nil
}

// keySchedule runs the HPKE Base-mode key schedule (RFC 9180 §5.1) and returns
// the AEAD for sequence number 0 together with its nonce.
func keySchedule(sharedSecret, info []byte) (aeadKey, nonce []byte, err error) {
	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	ctx := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ctx = append(ctx, 0) // mode_base
	ctx = append(ctx, pskIDHash...)
	ctx = append(ctx, infoHash...)
	secret, err := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	aeadKey, err = labeledExpand(hpkeSuiteID, secret, "key", ctx, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = labeledExpand(hpkeSuiteID, secret, "base_nonce", ctx, chacha20poly1305.NonceSize)
	return aeadKey, nonce, err
}

func dhkemSharedSecret(dh, enc, pkR []byte) ([]byte, error) {
	prk, err := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	kemContext := make([]byte, 0, len(enc)+len(pkR))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR...)
	return labeledExpand(kemSuiteID, prk, "shared_secret", kemContext, sha256.Size)
}

// HPKEBaseSeal is SealBase for DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
// ChaCha20Poly1305. It returns enc || ct.
//
// If ikmE is non-nil the ephemeral key pair is DeriveKeyPair(ikmE), which makes
// the output deterministic; this exists for reproducing published test
// vectors and must not be used otherwise. With ikmE nil, the ephemeral key is
// drawn from rng (crypto/rand if rng is nil).
func HPKEBaseSeal(pkR, info, aad, plaintext, ikmE []byte, rng io.Reader) ([]byte, error) {
	recipient, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver X25519 key: %v", ErrKey, err)
	}
	var eph *ecdh.PrivateKey
	if ikmE != nil {
		eph, err = X25519DeriveKeyPair(ikmE)
	} else {
		if rng == nil {
			rng = rand.Reader
		}
		seed := make([]byte, X25519KeySize)
		if _, err = io.ReadFull(rng, seed); err != nil {
			return nil, fmt.Errorf("tsp/crypto: reading randomness: %w", err)
		}
		eph, err = X25519DeriveKeyPair(seed)
	}
	if err != nil {
		return nil, err
	}
	dh, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519: %v", ErrKey, err)
	}
	enc := eph.PublicKey().Bytes()
	shared, err := dhkemSharedSecret(dh, enc, pkR)
	if err != nil {
		return nil, err
	}
	key, nonce, err := keySchedule(shared, info)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(enc)+len(plaintext)+AEADTagSize)
	out = append(out, enc...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// HPKEBaseOpen is OpenBase for the X25519 suite; ciphertext is enc || ct.
func HPKEBaseOpen(skR, info, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < HPKEBaseEncSize+AEADTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}
	priv, err := ecdh.X25519().NewPrivateKey(skR)
	if err != nil {
		return nil, fmt.Errorf("%w: receiver X25519 key: %v", ErrKey, err)
	}
	enc := ciphertext[:HPKEBaseEncSize]
	ephPub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: encapsulated key: %v", ErrDecrypt, err)
	}
	dh, err := priv.ECDH(ephPub)
	if err != nil {
		// All-zero shared secret: a small-order encapsulated key.
		return nil, fmt.Errorf("%w: X25519: %v", ErrDecrypt, err)
	}
	shared, err := dhkemSharedSecret(dh, enc, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	key, nonce, err := keySchedule(shared, info)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext[HPKEBaseEncSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// HPKE with the MLKEM768-X25519 hybrid KEM (draft-ietf-hpke-pq), 0x647a.

var pqKEM = hpke.MLKEM768X25519()

// HPKEPQPublicKey derives the 1216-byte public key from a 32-byte
// MLKEM768-X25519 private key seed.
func HPKEPQPublicKey(seed []byte) ([]byte, error) {
	if len(seed) != HPKEPQSeedSize {
		return nil, fmt.Errorf("%w: MLKEM768-X25519 seed of %d bytes", ErrKey, len(seed))
	}
	k, err := pqKEM.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return k.PublicKey().Bytes(), nil
}

// HPKEPQGenerateSeed returns a fresh MLKEM768-X25519 private key seed.
func HPKEPQGenerateSeed(rng io.Reader) ([]byte, error) {
	if rng == nil {
		rng = rand.Reader
	}
	seed := make([]byte, HPKEPQSeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// HPKEPQSeal is SealBase with KEM MLKEM768-X25519, KDF HKDF-SHA256 and AEAD
// ChaCha20Poly1305. It returns enc (1120 bytes) || ct. Encapsulation uses
// the system CSPRNG; it cannot be made deterministic.
func HPKEPQSeal(pkR, info, aad, plaintext []byte) ([]byte, error) {
	if len(pkR) != HPKEPQPublicKeySize {
		return nil, fmt.Errorf("%w: MLKEM768-X25519 public key of %d bytes", ErrKey, len(pkR))
	}
	pk, err := pqKEM.NewPublicKey(pkR)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, fmt.Errorf("tsp/crypto: hybrid encapsulation: %w", err)
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// HPKEPQOpen is OpenBase for the hybrid suite; ciphertext is enc || ct.
func HPKEPQOpen(seed, info, aad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < HPKEPQEncSize+AEADTagSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecrypt)
	}
	if len(seed) != HPKEPQSeedSize {
		return nil, fmt.Errorf("%w: MLKEM768-X25519 seed of %d bytes", ErrKey, len(seed))
	}
	sk, err := pqKEM.NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	r, err := hpke.NewRecipient(ciphertext[:HPKEPQEncSize], sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, fmt.Errorf("%w: decapsulation: %v", ErrDecrypt, err)
	}
	pt, err := r.Open(aad, ciphertext[HPKEPQEncSize:])
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
