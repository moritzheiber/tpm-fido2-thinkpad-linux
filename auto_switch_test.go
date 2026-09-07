package main

import "testing"

func TestAutoSwitchStateTransitions(t *testing.T) {
	state := autoSwitchState{automatic: true}

	if action := state.userEnable(); action != deviceStart {
		t.Fatalf("user enable action = %v", action)
	}
	if action := state.setKeyPresent(true); action != deviceStop || !state.stoppedByAuto {
		t.Fatalf("key insertion action = %v, stoppedByAuto=%v", action, state.stoppedByAuto)
	}
	if action := state.setKeyPresent(false); action != deviceStart || state.stoppedByAuto {
		t.Fatalf("key removal action = %v, stoppedByAuto=%v", action, state.stoppedByAuto)
	}
}

func TestManualDisableIsNotUndoneByKeyRemoval(t *testing.T) {
	state := autoSwitchState{automatic: true}
	state.userEnable()
	state.setKeyPresent(true)

	if action := state.userDisable(); action != deviceStop {
		t.Fatalf("user disable action = %v", action)
	}
	if action := state.setKeyPresent(false); action != deviceNone {
		t.Fatalf("key removal action = %v, want no action", action)
	}
}

func TestDisablingAutomaticSwitchRestoresDevice(t *testing.T) {
	state := autoSwitchState{automatic: true}
	state.userEnable()
	state.setKeyPresent(true)

	if action := state.setAutomatic(false); action != deviceStart {
		t.Fatalf("disable automatic action = %v", action)
	}
	if state.stoppedByAuto {
		t.Fatal("automatic stop marker was not cleared")
	}
}

func TestEnablingAutomaticSwitchStopsForPresentKey(t *testing.T) {
	state := autoSwitchState{}
	state.userEnable()
	state.setKeyPresent(true)

	if action := state.setAutomatic(true); action != deviceStop {
		t.Fatalf("enable automatic action = %v", action)
	}
}
