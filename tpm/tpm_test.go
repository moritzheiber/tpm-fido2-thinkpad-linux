package tpm

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/psanford/tpm-fido/internal/lencode"
)

// makeHandle builds a key handle in the same lencode framing that registerKey
// produces, so the handle-parsing paths can be tested without a TPM.
func makeHandle(t *testing.T, priv, pub, seed []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))
	for _, part := range [][]byte{priv, pub, seed} {
		if err := enc.Encode(part); err != nil {
			t.Fatalf("encode handle: %v", err)
		}
	}
	return out.Bytes()
}

func TestDeriveCredRandomMatchesHMAC(t *testing.T) {
	seed := []byte("0123456789abcdef0123")
	handle := makeHandle(t, []byte("private-blob"), []byte("public-blob"), seed)

	var tp TPM
	got, err := tp.DeriveCredRandom(handle)
	if err != nil {
		t.Fatalf("DeriveCredRandom: %v", err)
	}

	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("credential-random"))
	want := mac.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveCredRandom = %x, want %x", got, want)
	}
	if len(got) != sha256.Size {
		t.Fatalf("cred random length = %d, want %d", len(got), sha256.Size)
	}
}

func TestDeriveCredRandomDependsOnSeed(t *testing.T) {
	var tp TPM
	a, err := tp.DeriveCredRandom(makeHandle(t, []byte("p"), []byte("q"), []byte("seed-aaaaaaaaaaaaaa")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tp.DeriveCredRandom(makeHandle(t, []byte("p"), []byte("q"), []byte("seed-bbbbbbbbbbbbbb")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected different cred random for different seeds")
	}
}

func TestDeriveCredRandomInvalidHandle(t *testing.T) {
	var tp TPM

	var oneField bytes.Buffer
	enc := lencode.NewEncoder(&oneField, lencode.SeparatorOpt(separator))
	if err := enc.Encode([]byte("only-private")); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"truncated": oneField.Bytes(),
		"garbage":   []byte("not a valid handle"),
		"empty":     nil,
	}
	for name, handle := range cases {
		if _, err := tp.DeriveCredRandom(handle); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestPrimaryKeyTmplDeterministic(t *testing.T) {
	seed := []byte("seed-value-1234567890")
	app := []byte("rp-id.example")

	a := tpm2.Marshal(primaryKeyTmpl(seed, app))
	b := tpm2.Marshal(primaryKeyTmpl(seed, app))
	if !bytes.Equal(a, b) {
		t.Fatal("primaryKeyTmpl is not deterministic for identical inputs")
	}

	if bytes.Equal(a, tpm2.Marshal(primaryKeyTmpl(seed, []byte("other-rp.example")))) {
		t.Fatal("primaryKeyTmpl should differ for a different applicationParam")
	}

	if bytes.Equal(a, tpm2.Marshal(primaryKeyTmpl([]byte("different-seed-00000"), app))) {
		t.Fatal("primaryKeyTmpl should differ for a different seed")
	}
}

func TestChildKeyTmplMarshals(t *testing.T) {
	if len(tpm2.Marshal(childKeyTmpl())) == 0 {
		t.Fatal("childKeyTmpl marshaled to zero bytes")
	}
}
