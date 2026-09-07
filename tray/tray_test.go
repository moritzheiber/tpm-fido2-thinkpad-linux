package tray

import (
	"sync"
	"testing"
)

func TestStateUpdatesBeforeReadyAreRetained(t *testing.T) {
	tray := New(func() {}, func() {}, func() {}, func(bool) {})

	tray.SetActive(false)
	tray.SetAutoSwitch(false)
	tray.SetYubiKeyDetected(true, "YubiKey")

	tray.mu.Lock()
	defer tray.mu.Unlock()
	if tray.active || tray.automatic || !tray.keyPresent || tray.keyName != "YubiKey" {
		t.Fatalf("state was not retained: active=%v automatic=%v present=%v name=%q",
			tray.active, tray.automatic, tray.keyPresent, tray.keyName)
	}
}

func TestConcurrentStateUpdatesBeforeReady(t *testing.T) {
	tray := New(func() {}, func() {}, func() {}, func(bool) {})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				enabled := j%2 == 0
				tray.SetActive(enabled)
				tray.SetAutoSwitch(enabled)
				tray.SetYubiKeyDetected(enabled, "YubiKey")
			}
		})
	}
	wg.Wait()
}
