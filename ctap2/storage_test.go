package ctap2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyCredentialMetadataRemainsReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	legacy := `[{
		"rp_id":"example.com",
		"rp_name":"Example",
		"user_id":"YWxpY2U=",
		"user_name":"alice",
		"user_display_name":"Alice",
		"credential_id":"AQID",
		"public_key_x":"BA==",
		"public_key_y":"BQ==",
		"created_at":"2026-09-01T12:00:00Z"
	}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewCredentialStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	credentials := storage.GetByRPID("example.com")
	if len(credentials) != 1 || credentials[0].UserName != "alice" {
		t.Fatalf("credentials=%v", credentials)
	}
	if err := storage.Save(credentials[0]); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"rp_name", "public_key_x", "public_key_y", "created_at"} {
		if strings.Contains(string(data), removed) {
			t.Errorf("rewritten metadata still contains %q", removed)
		}
	}
}
