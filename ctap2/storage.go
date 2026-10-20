package ctap2

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// CredentialMetadata stores resident key credential information
type CredentialMetadata struct {
	RPID            string `json:"rp_id"`
	UserID          []byte `json:"user_id"`
	UserName        string `json:"user_name,omitempty"`
	UserDisplayName string `json:"user_display_name,omitempty"`
	CredentialID    []byte `json:"credential_id"`
}

// CredentialStorage manages persistent storage of resident credentials
type CredentialStorage struct {
	mu          sync.RWMutex
	filePath    string
	credentials []*CredentialMetadata
	// In-memory indexes for fast lookup
	byRPID map[string][]*CredentialMetadata
}

// NewCredentialStorage creates a new credential storage at the given path
func NewCredentialStorage(filePath string) (*CredentialStorage, error) {
	cs := &CredentialStorage{
		filePath:    filePath,
		credentials: make([]*CredentialMetadata, 0),
		byRPID:      make(map[string][]*CredentialMetadata),
	}

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	// Load existing credentials if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := cs.load(); err != nil {
			log.Printf("Warning: failed to load credentials from %s: %v", filePath, err)
			// Continue with empty storage
		}
	}

	return cs, nil
}

// load reads credentials from disk
func (cs *CredentialStorage) load() error {
	data, err := os.ReadFile(cs.filePath)
	if err != nil {
		return err
	}

	var credentials []*CredentialMetadata
	if err := json.Unmarshal(data, &credentials); err != nil {
		return err
	}

	cs.credentials = credentials
	cs.rebuildIndexes()

	log.Printf("CredentialStorage: Loaded %d credentials from %s", len(credentials), cs.filePath)
	return nil
}

// save writes credentials to disk
func (cs *CredentialStorage) save() error {
	data, err := json.MarshalIndent(cs.credentials, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically using temp file + rename
	tmpPath := cs.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, cs.filePath)
}

// rebuildIndexes rebuilds the in-memory lookup indexes
func (cs *CredentialStorage) rebuildIndexes() {
	cs.byRPID = make(map[string][]*CredentialMetadata)

	for _, cred := range cs.credentials {
		cs.byRPID[cred.RPID] = append(cs.byRPID[cred.RPID], cred)
	}
}

// Save stores a new credential, replacing any existing credential with same user ID for same RP
func (cs *CredentialStorage) Save(cred *CredentialMetadata) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Check if credential with same RPID and UserID already exists
	// Per WebAuthn spec, overwrite existing credential for same user
	found := false
	for i, existing := range cs.credentials {
		if existing.RPID == cred.RPID && bytes.Equal(existing.UserID, cred.UserID) {
			// Replace existing credential
			cs.credentials[i] = cred
			found = true
			log.Printf("CredentialStorage: Replaced credential for RP=%s, User=%s", cred.RPID, cred.UserName)
			break
		}
	}

	if !found {
		cs.credentials = append(cs.credentials, cred)
		log.Printf("CredentialStorage: Added new credential for RP=%s, User=%s", cred.RPID, cred.UserName)
	}

	cs.rebuildIndexes()

	if err := cs.save(); err != nil {
		log.Printf("CredentialStorage: Failed to save: %v", err)
		return err
	}

	return nil
}

// GetByRPID returns all credentials for a given relying party
func (cs *CredentialStorage) GetByRPID(rpId string) []*CredentialMetadata {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	// Return a copy to prevent mutation
	creds := cs.byRPID[rpId]
	if len(creds) == 0 {
		return nil
	}

	result := make([]*CredentialMetadata, len(creds))
	copy(result, creds)
	return result
}

// Count returns the number of stored credentials
func (cs *CredentialStorage) Count() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	return len(cs.credentials)
}
