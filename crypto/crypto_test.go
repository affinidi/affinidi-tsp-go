package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestX25519DeriveKeyPairRFC9180 checks DeriveKeyPair against the RFC 9180
// test vectors shipped with the Go standard library: for every
// DHKEM(X25519, HKDF-SHA256) vector, DeriveKeyPair(ikmE) must give enc and
// DeriveKeyPair(ikmR) must give skRm/pkRm.
func TestX25519DeriveKeyPairRFC9180(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src", "crypto", "hpke", "testdata", "rfc9180.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("RFC 9180 vectors not available: %v", err)
	}
	var vectors []struct {
		KEM  uint16 `json:"kem_id"`
		IkmE string `json:"ikmE"`
		IkmR string `json:"ikmR"`
		SkRm string `json:"skRm"`
		PkRm string `json:"pkRm"`
		Enc  string `json:"enc"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vectors {
		if v.KEM != KEMX25519HKDFSHA256 {
			continue
		}
		n++
		e, err := X25519DeriveKeyPair(unhex(t, v.IkmE))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(e.PublicKey().Bytes(), unhex(t, v.Enc)) {
			t.Errorf("DeriveKeyPair(ikmE) public key %x, want enc %x", e.PublicKey().Bytes(), unhex(t, v.Enc))
		}
		r, err := X25519DeriveKeyPair(unhex(t, v.IkmR))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.Bytes(), unhex(t, v.SkRm)) || !bytes.Equal(r.PublicKey().Bytes(), unhex(t, v.PkRm)) {
			t.Errorf("DeriveKeyPair(ikmR) = %x, want %x", r.Bytes(), unhex(t, v.SkRm))
		}
	}
	if n == 0 {
		t.Fatal("no X25519 vectors")
	}
}

// TestHPKEBaseInteroperatesWithStdlib checks the hand-rolled HPKE-Base suite
// against crypto/hpke in both directions, including aad and info binding.
func TestHPKEBaseInteroperatesWithStdlib(t *testing.T) {
	kem := hpke.DHKEM(ecdh.X25519())
	skR, err := kem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	skRBytes, err := skR.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pkR := skR.PublicKey().Bytes()
	info, aad := []byte("YTSP-"), []byte("associated data")
	for _, size := range []int{0, 1, 17, 4096} {
		pt := make([]byte, size)
		rand.Read(pt)

		// ours -> stdlib
		ct, err := HPKEBaseSeal(pkR, info, aad, pt, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := hpke.NewRecipient(ct[:32], skR, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Open(aad, ct[32:])
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("stdlib could not open our ciphertext: %v", err)
		}

		// stdlib -> ours
		pk, _ := kem.NewPublicKey(pkR)
		enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
		if err != nil {
			t.Fatal(err)
		}
		sct, err := s.Seal(aad, pt)
		if err != nil {
			t.Fatal(err)
		}
		got, err = HPKEBaseOpen(skRBytes, info, aad, append(enc, sct...))
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("we could not open the stdlib ciphertext: %v", err)
		}

		if _, err := HPKEBaseOpen(skRBytes, info, []byte("other aad"), ct); err == nil {
			t.Fatal("opened under a different aad")
		}
		if _, err := HPKEBaseOpen(skRBytes, []byte("other"), aad, ct); err == nil {
			t.Fatal("opened under a different info")
		}
	}
}

func TestHPKEBaseDeterministicWithIkmE(t *testing.T) {
	sk := make([]byte, 32)
	rand.Read(sk)
	pk, _ := X25519PublicKey(sk)
	ikm := bytes.Repeat([]byte{7}, 32)
	a, err := HPKEBaseSeal(pk, nil, nil, []byte("x"), ikm, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := HPKEBaseSeal(pk, nil, nil, []byte("x"), ikm, nil)
	if !bytes.Equal(a, b) {
		t.Fatal("same ikmE gave different ciphertexts")
	}
	c, _ := HPKEBaseSeal(pk, nil, nil, []byte("x"), nil, nil)
	if bytes.Equal(a, c) {
		t.Fatal("random encapsulation repeated")
	}
}

func TestHPKEBaseRejectsSmallOrderEnc(t *testing.T) {
	sk := make([]byte, 32)
	rand.Read(sk)
	ct := make([]byte, 32+16) // all-zero enc is a small-order point
	if _, err := HPKEBaseOpen(sk, nil, nil, ct); err == nil {
		t.Fatal("accepted a small-order encapsulated key")
	}
	zero := make([]byte, 32)
	if _, err := HPKEBaseSeal(zero, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("sealed to a small-order public key")
	}
}

func TestHPKEPQRoundTrip(t *testing.T) {
	seed, err := HPKEPQGenerateSeed(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := HPKEPQPublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := HPKEPQSeal(pk, []byte("YTSP-"), []byte("aad"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != HPKEPQEncSize+5+AEADTagSize {
		t.Fatalf("ciphertext length %d", len(ct))
	}
	pt, err := HPKEPQOpen(seed, []byte("YTSP-"), []byte("aad"), ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("open: %v", err)
	}
	if _, err := HPKEPQOpen(seed, []byte("YTSP-"), []byte("AAD"), ct); err == nil {
		t.Fatal("opened under a different aad")
	}
}

// TestSealedBoxMatchesNaCl checks our sealed box against x/crypto's
// SealAnonymous / OpenAnonymous, which implement libsodium's construction.
func TestSealedBoxMatchesNaCl(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("sealed box interop")
	ours, err := SealedBoxSeal(pub[:], msg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := box.OpenAnonymous(nil, ours, pub, priv)
	if !ok || !bytes.Equal(got, msg) {
		t.Fatal("x/crypto could not open our sealed box")
	}
	theirs, err := box.SealAnonymous(nil, msg, pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err = SealedBoxOpen(priv[:], theirs)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("we could not open x/crypto's sealed box: %v", err)
	}
	theirs[len(theirs)-1] ^= 1
	if _, err := SealedBoxOpen(priv[:], theirs); err == nil {
		t.Fatal("opened a tampered sealed box")
	}
}

func TestSignatures(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	pk, err := Ed25519PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := Ed25519Sign(seed, []byte("m"))
	if Ed25519Verify(pk, []byte("m"), sig) != nil || Ed25519Verify(pk, []byte("n"), sig) == nil {
		t.Fatal("Ed25519")
	}

	mpk, err := MLDSA65PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	msig, err := MLDSA65Sign(seed, []byte("m"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if MLDSA65Verify(mpk, []byte("m"), msig) != nil || MLDSA65Verify(mpk, []byte("n"), msig) == nil {
		t.Fatal("ML-DSA-65")
	}
	if _, err := MLDSA65Sign(make([]byte, 100), []byte("m"), nil); err == nil {
		t.Fatal("accepted a malformed ML-DSA-65 key")
	}
}
