package tpm

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (transport.TPMCloser, error) {
	return linuxtpm.Open(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}

	thetpm, err := t.open()
	if err != nil {
		return nil, err
	}
	thetpm.Close()

	return t, nil
}

// primaryKeyTmpl builds the parent (storage) key template. The unique point is
// derived from the seed and applicationParam so the same parent can be
// recreated deterministically when a key handle is reloaded.
func primaryKeyTmpl(seed, applicationParam []byte) tpm2.TPMTPublic {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	x := make([]byte, 32)
	y := make([]byte, 32)
	if _, err := io.ReadFull(r, x); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, y); err != nil {
		panic(err)
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:          true,
			Decrypt:             true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}
}

// childKeyTmpl builds the ECDSA P-256 signing key template.
func childKeyTmpl() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
	}
}

// flush releases a transient TPM handle, ignoring any error.
func flush(thetpm transport.TPM, handle tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: handle}.Execute(thetpm)
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

// RegisterKey creates a new signing key bound to applicationParam and returns
// the key handle together with the public key coordinates.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	thetpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer thetpm.Close()

	return registerKey(thetpm, applicationParam)
}

// registerKey creates a new signing key bound to applicationParam using the
// given TPM transport. It is split out from RegisterKey so the flow can be
// exercised against a TPM simulator in tests.
func registerKey(thetpm transport.TPM, applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	randSeed := mustRand(seedSizeBytes)

	primaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryKeyTmpl(randSeed, applicationParam)),
	}.Execute(thetpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}
	defer flush(thetpm, primaryRsp.ObjectHandle)

	childRsp, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryRsp.ObjectHandle,
			Name:   primaryRsp.Name,
		},
		InPublic: tpm2.New2B(childKeyTmpl()),
	}.Execute(thetpm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreateKey (child) err: %w", err)
	}

	pub, err := childRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read child public err: %w", err)
	}

	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read child ecc point err: %w", err)
	}

	x := new(big.Int).SetBytes(point.X.Buffer)
	y := new(big.Int).SetBytes(point.Y.Buffer)

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))
	enc.Encode(childRsp.OutPrivate.Buffer)
	enc.Encode(tpm2.Marshal(*pub))
	enc.Encode(randSeed)

	return out.Bytes(), x, y, nil
}

// DeriveCredRandom derives a credential-specific random value for hmac-secret extension
// Extracts the seed from the keyHandle and uses HMAC-SHA256(seed, "credential-random")
func (t *TPM) DeriveCredRandom(keyHandle []byte) ([]byte, error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	// Skip private key
	_, err := dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing private")
	}

	// Skip public key
	_, err = dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing public")
	}

	// Get seed
	seed, err := dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing seed")
	}

	// Derive credential random using HMAC-SHA256(seed, "credential-random")
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("credential-random"))
	return mac.Sum(nil), nil
}

// SignASN1 reloads the key referenced by keyHandle and signs digest, returning
// the signature as an ASN.1 ECDSA-Sig-Value (r, s) sequence.
func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	thetpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer thetpm.Close()

	return signASN1(thetpm, keyHandle, applicationParam, digest)
}

// signASN1 reloads the key referenced by keyHandle using the given TPM
// transport and signs digest. It is split out from SignASN1 so the flow can be
// exercised against a TPM simulator in tests.
func signASN1(thetpm transport.TPM, keyHandle, applicationParam, digest []byte) ([]byte, error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	invalidHandleErr := fmt.Errorf("invalid key handle")

	private, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	public, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	seed, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	_, err = dec.Decode()
	if err != io.EOF {
		return nil, invalidHandleErr
	}

	primaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryKeyTmpl(seed, applicationParam)),
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}
	defer flush(thetpm, primaryRsp.ObjectHandle)

	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryRsp.ObjectHandle,
			Name:   primaryRsp.Name,
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: private},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](public),
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}
	defer flush(thetpm, loadRsp.ObjectHandle)

	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(thetpm)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	ecc, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("extract ecdsa signature err: %w", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(ecc.SignatureR.Buffer))
		b.AddASN1BigInt(new(big.Int).SetBytes(ecc.SignatureS.Buffer))
	})

	return b.Bytes()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
