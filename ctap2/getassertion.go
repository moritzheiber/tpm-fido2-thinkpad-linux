package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// GetAssertion handles the authenticatorGetAssertion command
func (h *Handler) GetAssertion(ctx context.Context, req *GetAssertionRequest) (byte, []byte) {
	log.Printf("CTAP2 GetAssertion: RPID=%s, allowList=%d credentials", req.RPID, len(req.AllowList))

	// Clear any previous assertion state
	h.assertionState = nil

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 GetAssertion: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Compute rpIdHash
	rpIDHash := HashRPID(req.RPID)

	// Try to find credentials either from allowList or storage
	var matchedCredentials []*CredentialMetadata
	var matchedFromAllowList *PublicKeyCredentialDescriptor

	if len(req.AllowList) > 0 {
		// Path 1: Server-side credential (allowList provided)
		// Find a valid credential from the allowList by checking if we can sign with it
		for i := range req.AllowList {
			cred := &req.AllowList[i]
			// Try to sign with a dummy hash to check if credential is valid
			dummyHash := sha256.Sum256([]byte("credential-check"))
			_, err := h.signer.SignASN1(cred.ID, rpIDHash[:], dummyHash[:])
			if err == nil {
				matchedFromAllowList = cred
				log.Printf("CTAP2 GetAssertion: Found valid credential in allowList, ID length=%d", len(cred.ID))
				break
			}
		}

		if matchedFromAllowList == nil {
			log.Printf("CTAP2 GetAssertion: No valid credential found in allowList")
			return StatusNoCredentials, nil
		}
	} else {
		// Path 2: Resident key discovery (no allowList)
		// Look up credentials by rpId from storage
		if h.storage == nil {
			log.Printf("CTAP2 GetAssertion: No storage available for credential discovery")
			return StatusNoCredentials, nil
		}

		matchedCredentials = h.storage.GetByRPID(req.RPID)
		if len(matchedCredentials) == 0 {
			log.Printf("CTAP2 GetAssertion: No discoverable credentials found for RP=%s", req.RPID)
			return StatusNoCredentials, nil
		}

		log.Printf("CTAP2 GetAssertion: Found %d discoverable credential(s) for RP=%s", len(matchedCredentials), req.RPID)

		// Verify each credential is still valid (can still sign with it)
		validCredentials := make([]*CredentialMetadata, 0, len(matchedCredentials))
		for _, cred := range matchedCredentials {
			dummyHash := sha256.Sum256([]byte("credential-check"))
			_, err := h.signer.SignASN1(cred.CredentialID, rpIDHash[:], dummyHash[:])
			if err == nil {
				validCredentials = append(validCredentials, cred)
			} else {
				log.Printf("CTAP2 GetAssertion: Stored credential no longer valid (TPM key deleted?), user=%s", cred.UserName)
			}
		}

		if len(validCredentials) == 0 {
			log.Printf("CTAP2 GetAssertion: All stored credentials are invalid")
			return StatusNoCredentials, nil
		}

		matchedCredentials = validCredentials
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence(AuthenticationPrompt(req.RPID), challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			log.Printf("CTAP2 GetAssertion: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 GetAssertion: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Handle the two different paths for response building
	if matchedFromAllowList != nil {
		// Non-resident credential path - use the old behavior
		return h.buildNonResidentAssertionResponse(ctx, matchedFromAllowList, rpIDHash, req.ClientDataHash, req.Extensions)
	}

	// Resident credential path
	// Store state for GetNextAssertion if multiple credentials
	if len(matchedCredentials) > 1 {
		h.assertionState = &assertionState{
			credentials:     matchedCredentials,
			currentIndex:    0,
			rpIDHash:        rpIDHash,
			clientDataHash:  req.ClientDataHash,
			extensionsInput: req.Extensions,
		}
	}

	// Return the first credential
	return h.buildAssertionResponse(ctx, matchedCredentials[0], rpIDHash, req.ClientDataHash, req.Extensions, len(matchedCredentials), true)
}

// buildNonResidentAssertionResponse builds a response for non-resident (server-side) credentials
func (h *Handler) buildNonResidentAssertionResponse(ctx context.Context, cred *PublicKeyCredentialDescriptor, rpIDHash [32]byte, clientDataHash []byte, extensions map[string]interface{}) (byte, []byte) {
	// Process hmac-secret extension if present
	var extensionsOutput []byte
	log.Printf("CTAP2 GetAssertion: Extensions=%+v", extensions)
	if extensions != nil {
		for k, v := range extensions {
			log.Printf("CTAP2 GetAssertion: Extension key=%q, value type=%T", k, v)
		}
		if hmacSecretInput, ok := extensions["hmac-secret"]; ok {
			log.Printf("CTAP2 GetAssertion: Processing hmac-secret extension")
			hmacOutput, err := h.processHmacSecret(cred.ID, hmacSecretInput)
			if err != nil {
				log.Printf("CTAP2 GetAssertion: hmac-secret error: %s", err)
				return StatusExtensionFirst, nil
			}
			extMap := map[string][]byte{"hmac-secret": hmacOutput}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified)
	if len(extensionsOutput) > 0 {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData (no attested credential data for assertion)
	authData := &AuthenticatorData{
		RPIDHash:   rpIDHash,
		Flags:      flags,
		SignCount:  h.signer.Counter(),
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Sign authData || clientDataHash
	toSign := append(authDataBytes, clientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := h.signer.SignASN1(cred.ID, rpIDHash[:], sigHash[:])
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Sign error: %s", err)
		return StatusOther, nil
	}

	// Build response
	resp := &GetAssertionResponse{
		Credential: &PublicKeyCredentialDescriptor{
			Type: CredentialTypePublicKey,
			ID:   cred.ID,
		},
		AuthData:  authDataBytes,
		Signature: sig,
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 GetAssertion: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// buildAssertionResponse builds a response for resident (discoverable) credentials
func (h *Handler) buildAssertionResponse(ctx context.Context, cred *CredentialMetadata, rpIDHash [32]byte, clientDataHash []byte, extensions map[string]interface{}, totalCredentials int, isFirstResponse bool) (byte, []byte) {
	// Process hmac-secret extension if present
	var extensionsOutput []byte
	if isFirstResponse {
		log.Printf("CTAP2 GetAssertion: Extensions=%+v", extensions)
	}
	if extensions != nil {
		if isFirstResponse {
			for k, v := range extensions {
				log.Printf("CTAP2 GetAssertion: Extension key=%q, value type=%T", k, v)
			}
		}
		if hmacSecretInput, ok := extensions["hmac-secret"]; ok {
			log.Printf("CTAP2 GetAssertion: Processing hmac-secret extension for credential user=%s", cred.UserName)
			hmacOutput, err := h.processHmacSecret(cred.CredentialID, hmacSecretInput)
			if err != nil {
				log.Printf("CTAP2 GetAssertion: hmac-secret error: %s", err)
				return StatusExtensionFirst, nil
			}
			extMap := map[string][]byte{"hmac-secret": hmacOutput}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified)
	if len(extensionsOutput) > 0 {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData (no attested credential data for assertion)
	authData := &AuthenticatorData{
		RPIDHash:   rpIDHash,
		Flags:      flags,
		SignCount:  h.signer.Counter(),
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Sign authData || clientDataHash
	toSign := append(authDataBytes, clientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := h.signer.SignASN1(cred.CredentialID, rpIDHash[:], sigHash[:])
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Sign error: %s", err)
		return StatusOther, nil
	}

	// Build response with User field for resident credentials
	resp := &GetAssertionResponse{
		Credential: &PublicKeyCredentialDescriptor{
			Type: CredentialTypePublicKey,
			ID:   cred.CredentialID,
		},
		AuthData:  authDataBytes,
		Signature: sig,
		User: &PublicKeyCredentialUserEntity{
			ID:          cred.UserID,
			Name:        cred.UserName,
			DisplayName: cred.UserDisplayName,
		},
	}

	// Include numberOfCredentials in first response if there are multiple
	if isFirstResponse && totalCredentials > 1 {
		resp.NumberOfCredentials = uint(totalCredentials)
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 GetAssertion: Success (resident, user=%s), response=%d bytes", cred.UserName, len(encoded))
	return StatusSuccess, encoded
}

// parseGetAssertionRequest parses the CBOR-encoded GetAssertion request
func parseGetAssertionRequest(data []byte) (*GetAssertionRequest, error) {
	var req GetAssertionRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}
