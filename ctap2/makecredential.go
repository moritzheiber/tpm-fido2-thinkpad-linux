package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MakeCredential handles the authenticatorMakeCredential command
func (h *Handler) MakeCredential(ctx context.Context, req *MakeCredentialRequest) (byte, []byte) {
	log.Printf("CTAP2 MakeCredential: RP=%s, User=%s", req.RP.ID, req.User.Name)
	log.Printf("CTAP2 MakeCredential: Options=%+v", req.Options)
	log.Printf("CTAP2 MakeCredential: Extensions=%+v", req.Extensions)

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 MakeCredential: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Check if at least one supported algorithm is requested
	es256Supported := false
	for _, param := range req.PubKeyCredParams {
		if param.Type == CredentialTypePublicKey && param.Alg == COSEAlgES256 {
			es256Supported = true
			break
		}
	}
	if !es256Supported {
		log.Printf("CTAP2 MakeCredential: ES256 not in requested algorithms")
		return StatusUnsupportedAlgorithm, nil
	}

	rpIDHash := HashRPID(req.RP.ID)

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence(RegistrationPrompt(req.RP.Name, req.RP.ID), challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Credential existence is checked only after user consent.
	for _, excluded := range req.ExcludeList {
		dummyHash := sha256.Sum256([]byte("exclude-check"))
		if _, err := h.signer.SignASN1(excluded.ID, rpIDHash[:], dummyHash[:]); err == nil {
			log.Printf("CTAP2 MakeCredential: Credential in excludeList exists")
			return StatusCredentialExcluded, nil
		}
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			log.Printf("CTAP2 MakeCredential: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 MakeCredential: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Check if resident key is requested
	residentKeyRequested := false
	if req.Options != nil {
		if rk, ok := req.Options["rk"]; ok && rk {
			residentKeyRequested = true
		}
	}

	// Generate credential
	credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: RegisterKey error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Generated credential, ID length=%d, residentKey=%v", len(credentialID), residentKeyRequested)

	// Save resident credential if requested
	if residentKeyRequested && h.storage != nil {
		cred := &CredentialMetadata{
			RPID:            req.RP.ID,
			UserID:          req.User.ID,
			UserName:        req.User.Name,
			UserDisplayName: req.User.DisplayName,
			CredentialID:    credentialID,
		}
		if err := h.storage.Save(cred); err != nil {
			log.Printf("CTAP2 MakeCredential: Failed to save resident credential: %s", err)
			// Continue anyway - the credential is still valid, just not discoverable
		}
	}

	// Build COSE public key
	coseKey, err := BuildCOSEPublicKeyES256(x, y)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: COSE key build error: %s", err)
		return StatusOther, nil
	}

	// Build extensions output if hmac-secret was requested
	var extensionsOutput []byte
	hmacSecretRequested := false
	if req.Extensions != nil {
		if _, ok := req.Extensions["hmac-secret"]; ok {
			hmacSecretRequested = true
			extMap := map[string]bool{"hmac-secret": true}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified | FlagAttestedCredData)
	if hmacSecretRequested {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData
	authData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: h.signer.Counter(),
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              h.aaguid,
			CredentialID:        credentialID,
			CredentialPublicKey: coseKey,
		},
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Build response
	resp := &MakeCredentialResponse{
		Fmt:      "none",
		AuthData: authDataBytes,
		AttStmt:  map[string]interface{}{},
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// parseMakeCredentialRequest parses the CBOR-encoded MakeCredential request
func parseMakeCredentialRequest(data []byte) (*MakeCredentialRequest, error) {
	var req MakeCredentialRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}
