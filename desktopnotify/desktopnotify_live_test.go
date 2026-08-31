//go:build desktop

package desktopnotify

import (
	"context"
	"testing"
	"time"
)

func TestLiveNotificationReplacement(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Show(ctx, "TPM-FIDO test", "Initial notification"); err != nil {
		t.Fatalf("initial Show: %v", err)
	}
	if err := client.Show(ctx, "TPM-FIDO test", "Replacement notification"); err != nil {
		t.Fatalf("replacement Show: %v", err)
	}
}
