// Package tray provides a GNOME system tray icon for toggling the
// tpm-fido virtual FIDO2 device on and off.
//
// It uses fyne.io/systray which implements the D-Bus StatusNotifierItem
// protocol in pure Go — no CGo or GTK required. Works with Ubuntu's
// pre-installed gnome-shell-extension-appindicator.
package tray

import (
	_ "embed"
	"log"
	"sync"

	"fyne.io/systray"
)

//go:embed icons/active.png
var iconActive []byte

//go:embed icons/inactive.png
var iconInactive []byte

// Tray manages the system tray icon and menu for toggling the virtual
// FIDO2 device.
type Tray struct {
	mu sync.Mutex

	onEnable            func()
	onDisable           func()
	onQuit              func()
	onAutoSwitchChanged func(bool)

	toggle     *systray.MenuItem
	status     *systray.MenuItem
	autoSwitch *systray.MenuItem
	yubiStatus *systray.MenuItem
	ready      bool
	active     bool
	automatic  bool
	keyPresent bool
	keyName    string
}

// New creates a new Tray. The callbacks are invoked when the user clicks
// the corresponding menu items. onEnable/onDisable toggle the virtual
// HID device; onQuit stops the daemon; onAutoSwitchChanged is called
// when the auto-switch checkbox is toggled.
func New(onEnable, onDisable, onQuit func(), onAutoSwitchChanged func(bool)) *Tray {
	return &Tray{
		onEnable:            onEnable,
		onDisable:           onDisable,
		onQuit:              onQuit,
		onAutoSwitchChanged: onAutoSwitchChanged,
		active:              true,
		automatic:           true,
	}
}

// Run starts the system tray icon. It blocks until the tray exits.
// Must be called from the main goroutine on some platforms.
func (t *Tray) Run() {
	systray.Run(t.onReady, t.onExit)
}

// SetActive updates the tray icon and menu labels to reflect whether
// the virtual FIDO2 device is currently active.
func (t *Tray) SetActive(active bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = active
	if !t.ready {
		return
	}
	t.applyActiveLocked()
}

func (t *Tray) applyActiveLocked() {
	if t.active {
		systray.SetIcon(iconActive)
		systray.SetTooltip("TPM FIDO: Active")
		t.status.SetTitle("TPM FIDO: Active")
		t.toggle.SetTitle("Disable Fingerprint Key")
	} else {
		systray.SetIcon(iconInactive)
		systray.SetTooltip("TPM FIDO: Disabled")
		t.status.SetTitle("TPM FIDO: Disabled")
		t.toggle.SetTitle("Enable Fingerprint Key")
	}
}

// SetAutoSwitch updates the auto-switch checkbox state.
func (t *Tray) SetAutoSwitch(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.automatic = enabled
	if !t.ready {
		return
	}
	if enabled {
		t.autoSwitch.Check()
	} else {
		t.autoSwitch.Uncheck()
	}
}

// SetYubiKeyDetected shows or hides the YubiKey status menu item.
func (t *Tray) SetYubiKeyDetected(detected bool, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keyPresent = detected
	t.keyName = name
	if !t.ready {
		return
	}
	t.applyKeyStateLocked()
}

func (t *Tray) applyKeyStateLocked() {
	detected, name := t.keyPresent, t.keyName
	if detected {
		t.yubiStatus.SetTitle(name + " detected")
		t.yubiStatus.Show()
	} else {
		t.yubiStatus.Hide()
	}
}

func (t *Tray) onReady() {
	t.mu.Lock()
	defer t.mu.Unlock()
	systray.SetTitle("TPM FIDO")

	t.status = systray.AddMenuItem("TPM FIDO: Active", "")
	t.status.Disable() // non-clickable status line

	systray.AddSeparator()

	t.toggle = systray.AddMenuItem("Disable Fingerprint Key", "Toggle virtual FIDO2 device")

	systray.AddSeparator()

	t.autoSwitch = systray.AddMenuItemCheckbox("Auto-switch on YubiKey", "Automatically disable virtual key when YubiKey is plugged in", t.automatic)

	t.yubiStatus = systray.AddMenuItem("", "")
	t.yubiStatus.Disable() // non-clickable
	t.yubiStatus.Hide()    // hidden until a YubiKey is detected

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Stop the tpm-fido daemon")

	t.ready = true
	t.applyActiveLocked()
	if t.automatic {
		t.autoSwitch.Check()
	} else {
		t.autoSwitch.Uncheck()
	}
	t.applyKeyStateLocked()

	go func() {
		for {
			select {
			case <-t.toggle.ClickedCh:
				t.mu.Lock()
				active := t.active
				t.mu.Unlock()
				if active {
					log.Printf("tray: user requested disable")
					t.onDisable()
				} else {
					log.Printf("tray: user requested enable")
					t.onEnable()
				}
			case <-t.autoSwitch.ClickedCh:
				t.mu.Lock()
				enabled := !t.automatic
				t.mu.Unlock()
				log.Printf("tray: auto-switch toggled to %v", enabled)
				if t.onAutoSwitchChanged != nil {
					t.onAutoSwitchChanged(enabled)
				}
			case <-mQuit.ClickedCh:
				log.Printf("tray: user requested quit")
				t.onQuit()
				systray.Quit()
				return
			}
		}
	}()
}

func (t *Tray) onExit() {
	log.Printf("tray: exiting")
}
