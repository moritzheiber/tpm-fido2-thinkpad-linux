package ctap2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/userpresence"
)

type handlerTestSigner struct {
	keys          map[string]*ecdsa.PrivateKey
	applications  map[string][]byte
	signDigests   [][]byte
	registerCalls int
	counter       uint32
}

func newHandlerTestSigner() *handlerTestSigner {
	return &handlerTestSigner{
		keys:         make(map[string]*ecdsa.PrivateKey),
		applications: make(map[string][]byte),
	}
}

func (s *handlerTestSigner) RegisterKey(application []byte) ([]byte, *big.Int, *big.Int, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	s.registerCalls++
	id := []byte{byte(s.registerCalls), 0xa5, 0x5a}
	s.keys[string(id)] = key
	s.applications[string(id)] = bytes.Clone(application)
	return id, key.X, key.Y, nil
}

func (s *handlerTestSigner) SignASN1(id, application, digest []byte) ([]byte, error) {
	key := s.keys[string(id)]
	if key == nil || !bytes.Equal(s.applications[string(id)], application) {
		return nil, errors.New("invalid credential")
	}
	s.signDigests = append(s.signDigests, bytes.Clone(digest))
	return ecdsa.SignASN1(rand.Reader, key, digest)
}

func (s *handlerTestSigner) Counter() uint32 {
	s.counter++
	return s.counter
}

func (s *handlerTestSigner) DeriveCredRandom(id []byte) ([]byte, error) {
	sum := sha256.Sum256(id)
	return sum[:], nil
}

type handlerTestPresence struct {
	prompts []string
	result  userpresence.Result
	err     error
}

func (p *handlerTestPresence) ConfirmPresence(prompt string, _, _ [32]byte) (chan userpresence.Result, error) {
	p.prompts = append(p.prompts, prompt)
	if p.err != nil {
		return nil, p.err
	}
	result := make(chan userpresence.Result, 1)
	result <- p.result
	close(result)
	return result, nil
}

func newHandlerTestStorage(t *testing.T) *CredentialStorage {
	t.Helper()
	storage, err := NewCredentialStorage(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	return storage
}

func marshalCTAP(t *testing.T, value any) []byte {
	t.Helper()
	data, err := ctapEncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertCanonicalCBOR(t *testing.T, data []byte) {
	t.Helper()
	var value any
	if err := cbor.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	canonical, err := ctapEncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, canonical) {
		t.Fatal("response is not canonical CBOR")
	}
}

func makeCredentialRequest(rpID, rpName, user string, resident bool) MakeCredentialRequest {
	options := map[string]bool(nil)
	if resident {
		options = map[string]bool{"rk": true}
	}
	return MakeCredentialRequest{
		ClientDataHash: bytes.Repeat([]byte{0x11}, 32),
		RP: PublicKeyCredentialRpEntity{
			ID: rpID, Name: rpName,
		},
		User: PublicKeyCredentialUserEntity{
			ID: []byte(user), Name: user + "@" + rpID, DisplayName: user,
		},
		PubKeyCredParams: []PublicKeyCredentialParameters{{
			Type: CredentialTypePublicKey, Alg: COSEAlgES256,
		}},
		Options: options,
	}
}

func decodeCredentialID(t *testing.T, authData []byte) []byte {
	t.Helper()
	const prefix = 32 + 1 + 4 + 16
	if len(authData) < prefix+2 {
		t.Fatalf("authenticator data too short: %d", len(authData))
	}
	size := int(authData[prefix])<<8 | int(authData[prefix+1])
	start := prefix + 2
	if len(authData) < start+size {
		t.Fatal("credential ID exceeds authenticator data")
	}
	return bytes.Clone(authData[start : start+size])
}

func TestGetInfoCapabilitiesAndCanonicalEncoding(t *testing.T) {
	handler := NewHandler(newHandlerTestSigner(), &handlerTestPresence{}, newHandlerTestStorage(t))
	status, response := handler.HandleCommand(context.Background(), CmdGetInfo, nil)
	if status != StatusSuccess {
		t.Fatalf("status=%#x", status)
	}
	assertCanonicalCBOR(t, response)
	var info GetInfoResponse
	if err := cbor.Unmarshal(response, &info); err != nil {
		t.Fatal(err)
	}
	if !contains(info.Versions, "FIDO_2_1") || !contains(info.Extensions, "hmac-secret") {
		t.Fatalf("unexpected capabilities: versions=%v extensions=%v", info.Versions, info.Extensions)
	}
	if !info.Options["rk"] || !info.Options["up"] || !info.Options["uv"] {
		t.Fatalf("unexpected options: %v", info.Options)
	}
}

func TestMakeCredentialUsesNoneAttestationAndRelyingPartyPrompt(t *testing.T) {
	signer := newHandlerTestSigner()
	presence := &handlerTestPresence{result: userpresence.Result{OK: true}}
	handler := NewHandler(signer, presence, newHandlerTestStorage(t))
	request := makeCredentialRequest("example.com", "Example", "alice", false)

	status, encoded := handler.HandleCommand(context.Background(), CmdMakeCredential, marshalCTAP(t, request))
	if status != StatusSuccess {
		t.Fatalf("status=%#x", status)
	}
	assertCanonicalCBOR(t, encoded)
	var response MakeCredentialResponse
	if err := cbor.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response.Fmt != "none" || len(response.AttStmt) != 0 {
		t.Fatalf("attestation format=%q statement=%v", response.Fmt, response.AttStmt)
	}
	if got := presence.prompts; len(got) != 1 || got[0] != "Register a passkey for Example (example.com)" {
		t.Fatalf("prompts=%v", got)
	}
	if len(signer.signDigests) != 0 {
		t.Fatal("none attestation unexpectedly used an attestation signing key")
	}
}

func TestMakeCredentialRejectsUnsupportedAlgorithm(t *testing.T) {
	handler := NewHandler(newHandlerTestSigner(), &handlerTestPresence{}, newHandlerTestStorage(t))
	request := makeCredentialRequest("example.com", "Example", "alice", false)
	request.PubKeyCredParams[0].Alg = -257
	status, _ := handler.HandleCommand(context.Background(), CmdMakeCredential, marshalCTAP(t, request))
	if status != StatusUnsupportedAlgorithm {
		t.Fatalf("status=%#x, want %#x", status, StatusUnsupportedAlgorithm)
	}
}

func TestMakeCredentialChecksExcludeListAfterPresence(t *testing.T) {
	signer := newHandlerTestSigner()
	rpHash := HashRPID("example.com")
	existing, _, _, err := signer.RegisterKey(rpHash[:])
	if err != nil {
		t.Fatal(err)
	}
	presence := &handlerTestPresence{result: userpresence.Result{OK: true}}
	handler := NewHandler(signer, presence, newHandlerTestStorage(t))
	request := makeCredentialRequest("example.com", "Example", "alice", false)
	request.ExcludeList = []PublicKeyCredentialDescriptor{{Type: CredentialTypePublicKey, ID: existing}}

	status, _ := handler.HandleCommand(context.Background(), CmdMakeCredential, marshalCTAP(t, request))
	if status != StatusCredentialExcluded {
		t.Fatalf("status=%#x", status)
	}
	if len(presence.prompts) != 1 {
		t.Fatal("credential existence was disclosed without user presence")
	}
}

func TestGetAssertionPromptAndSignature(t *testing.T) {
	signer := newHandlerTestSigner()
	rpHash := HashRPID("example.com")
	credential, x, y, err := signer.RegisterKey(rpHash[:])
	if err != nil {
		t.Fatal(err)
	}
	presence := &handlerTestPresence{result: userpresence.Result{OK: true}}
	handler := NewHandler(signer, presence, newHandlerTestStorage(t))
	clientHash := bytes.Repeat([]byte{0x33}, 32)
	request := GetAssertionRequest{
		RPID: "example.com", ClientDataHash: clientHash,
		AllowList: []PublicKeyCredentialDescriptor{
			{Type: CredentialTypePublicKey, ID: []byte("invalid")},
			{Type: CredentialTypePublicKey, ID: credential},
		},
	}
	status, encoded := handler.HandleCommand(context.Background(), CmdGetAssertion, marshalCTAP(t, request))
	if status != StatusSuccess {
		t.Fatalf("status=%#x", status)
	}
	assertCanonicalCBOR(t, encoded)
	var response GetAssertionResponse
	if err := cbor.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Credential.ID, credential) {
		t.Fatalf("credential=%x", response.Credential.ID)
	}
	if got := presence.prompts; len(got) != 1 || got[0] != "Sign in to example.com" {
		t.Fatalf("prompts=%v", got)
	}
	digestInput := append(bytes.Clone(response.AuthData), clientHash...)
	digest := sha256.Sum256(digestInput)
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.VerifyASN1(public, digest[:], response.Signature) {
		t.Fatal("assertion signature does not cover authData and clientDataHash")
	}
}

func TestGetAssertionDoesNotPromptWithoutValidCredential(t *testing.T) {
	presence := &handlerTestPresence{result: userpresence.Result{OK: true}}
	handler := NewHandler(newHandlerTestSigner(), presence, newHandlerTestStorage(t))
	request := GetAssertionRequest{
		RPID: "example.com", ClientDataHash: bytes.Repeat([]byte{0x44}, 32),
		AllowList: []PublicKeyCredentialDescriptor{{Type: CredentialTypePublicKey, ID: []byte("invalid")}},
	}
	status, _ := handler.HandleCommand(context.Background(), CmdGetAssertion, marshalCTAP(t, request))
	if status != StatusNoCredentials || len(presence.prompts) != 0 {
		t.Fatalf("status=%#x prompts=%v", status, presence.prompts)
	}
}

func TestResidentCredentialsUseGetNextAssertion(t *testing.T) {
	signer := newHandlerTestSigner()
	storage := newHandlerTestStorage(t)
	rpHash := HashRPID("example.com")
	for _, user := range []string{"alice", "bob"} {
		id, _, _, err := signer.RegisterKey(rpHash[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := storage.Save(&CredentialMetadata{
			RPID: "example.com", UserID: []byte(user), UserName: user,
			CredentialID: id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHandler(signer, &handlerTestPresence{result: userpresence.Result{OK: true}}, storage)
	request := GetAssertionRequest{
		RPID: "example.com", ClientDataHash: bytes.Repeat([]byte{0x55}, 32),
	}
	status, firstData := handler.HandleCommand(context.Background(), CmdGetAssertion, marshalCTAP(t, request))
	if status != StatusSuccess {
		t.Fatalf("first status=%#x", status)
	}
	var first GetAssertionResponse
	if err := cbor.Unmarshal(firstData, &first); err != nil {
		t.Fatal(err)
	}
	if first.NumberOfCredentials != 2 {
		t.Fatalf("numberOfCredentials=%d", first.NumberOfCredentials)
	}
	status, nextData := handler.HandleCommand(context.Background(), CmdGetNextAssertion, nil)
	if status != StatusSuccess {
		t.Fatalf("next status=%#x", status)
	}
	var next GetAssertionResponse
	if err := cbor.Unmarshal(nextData, &next); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Credential.ID, next.Credential.ID) {
		t.Fatal("GetNextAssertion returned the first credential again")
	}
	if status, _ := handler.HandleCommand(context.Background(), CmdGetNextAssertion, nil); status != StatusNotAllowed {
		t.Fatalf("exhausted GetNextAssertion status=%#x", status)
	}
}

func TestRelyingPartyRegistrationAndAuthenticationScenarios(t *testing.T) {
	for _, rpID := range []string{
		"github.com",
		"accounts.google.com",
		"login.microsoftonline.com",
	} {
		t.Run(rpID, func(t *testing.T) {
			signer := newHandlerTestSigner()
			presence := &handlerTestPresence{result: userpresence.Result{OK: true}}
			handler := NewHandler(signer, presence, newHandlerTestStorage(t))
			request := makeCredentialRequest(rpID, rpID, "user", false)
			request.Options = map[string]bool{"uv": true}
			status, encoded := handler.HandleCommand(context.Background(), CmdMakeCredential, marshalCTAP(t, request))
			if status != StatusSuccess {
				t.Fatalf("registration status=%#x", status)
			}
			var registration MakeCredentialResponse
			if err := cbor.Unmarshal(encoded, &registration); err != nil {
				t.Fatal(err)
			}
			credential := decodeCredentialID(t, registration.AuthData)
			assertion := GetAssertionRequest{
				RPID: rpID, ClientDataHash: bytes.Repeat([]byte{0x77}, 32),
				AllowList: []PublicKeyCredentialDescriptor{{
					Type: CredentialTypePublicKey, ID: credential,
				}},
				Options: map[string]bool{"uv": true},
			}
			status, encoded = handler.HandleCommand(context.Background(), CmdGetAssertion, marshalCTAP(t, assertion))
			if status != StatusSuccess {
				t.Fatalf("authentication status=%#x", status)
			}
			var response GetAssertionResponse
			if err := cbor.Unmarshal(encoded, &response); err != nil {
				t.Fatal(err)
			}
			if len(response.AuthData) < 33 || response.AuthData[32]&FlagUserVerified == 0 {
				t.Fatal("authentication response omitted user verification")
			}
		})
	}
}

func TestCommandErrorStatuses(t *testing.T) {
	handler := NewHandler(newHandlerTestSigner(), &handlerTestPresence{}, newHandlerTestStorage(t))
	if status, _ := handler.HandleCommand(context.Background(), CmdMakeCredential, []byte{0xff}); status != StatusInvalidCBOR {
		t.Fatalf("MakeCredential malformed CBOR status=%#x", status)
	}
	if status, _ := handler.HandleCommand(context.Background(), CmdGetAssertion, []byte{0xff}); status != StatusInvalidCBOR {
		t.Fatalf("GetAssertion malformed CBOR status=%#x", status)
	}
	if status, _ := handler.HandleCommand(context.Background(), 0xfe, nil); status != StatusInvalidCommand {
		t.Fatalf("unknown command status=%#x", status)
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
