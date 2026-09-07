//go:build fingerprint

package fprintd

import (
	"context"
	"testing"
	"time"
)

func TestLiveAnyFinger(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Verify(ctx, "", func(hint string) { t.Log(hint) }); err != nil {
		t.Fatal(err)
	}
}
