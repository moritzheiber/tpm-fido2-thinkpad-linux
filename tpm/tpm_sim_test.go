//go:build tpmsim

// Package tpm simulator integration tests. These run only with the "tpmsim"
// build tag because they depend on the CGO-based go-tpm-tools simulator, which
// needs a C toolchain and OpenSSL headers. Run them with:
//
//	go test -tags tpmsim ./tpm/...
package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestRegisterSignRoundtripSimulator(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	defer thetpm.Close()

	app := sha256.Sum256([]byte("webauthn.io"))

	handle, x, y, err := registerKey(thetpm, app[:])
	if err != nil {
		t.Fatalf("registerKey: %v", err)
	}
	if len(handle) == 0 || x.Sign() == 0 || y.Sign() == 0 {
		t.Fatalf("unexpected empty handle or public point")
	}

	digest := sha256.Sum256([]byte("assertion challenge"))
	der, err := signASN1(thetpm, handle, app[:], digest[:])
	if err != nil {
		t.Fatalf("signASN1: %v", err)
	}

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatalf("signature did not verify against the returned public key")
	}

	bad := sha256.Sum256([]byte("different challenge"))
	if ecdsa.VerifyASN1(pub, bad[:], der) {
		t.Fatalf("signature must not verify against a different digest")
	}
}

func TestSignRejectsForeignHandleSimulator(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	defer thetpm.Close()

	app := sha256.Sum256([]byte("example.org"))
	handle, _, _, err := registerKey(thetpm, app[:])
	if err != nil {
		t.Fatalf("registerKey: %v", err)
	}

	// A handle bound to one applicationParam must not load under another.
	other := sha256.Sum256([]byte("attacker.example"))
	digest := sha256.Sum256([]byte("challenge"))
	if _, err := signASN1(thetpm, handle, other[:], digest[:]); err == nil {
		t.Fatalf("expected sign to fail when applicationParam does not match")
	}
}

func TestDeriveCredRandomStableSimulator(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	defer thetpm.Close()

	app := sha256.Sum256([]byte("example.org"))
	handle, _, _, err := registerKey(thetpm, app[:])
	if err != nil {
		t.Fatalf("registerKey: %v", err)
	}

	var tp TPM
	r1, err := tp.DeriveCredRandom(handle)
	if err != nil {
		t.Fatalf("DeriveCredRandom: %v", err)
	}
	r2, err := tp.DeriveCredRandom(handle)
	if err != nil {
		t.Fatalf("DeriveCredRandom: %v", err)
	}
	if !bytesEqual(r1, r2) {
		t.Fatalf("cred random is not stable across calls")
	}
	if len(r1) != sha256.Size {
		t.Fatalf("cred random length = %d, want %d", len(r1), sha256.Size)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
