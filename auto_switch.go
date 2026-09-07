package main

type deviceAction uint8

const (
	deviceNone deviceAction = iota
	deviceStart
	deviceStop
)

type autoSwitchState struct {
	automatic     bool
	keyPresent    bool
	stoppedByAuto bool
}

func (s *autoSwitchState) userEnable() deviceAction {
	s.stoppedByAuto = false
	return deviceStart
}

func (s *autoSwitchState) userDisable() deviceAction {
	s.stoppedByAuto = false
	return deviceStop
}

func (s *autoSwitchState) setAutomatic(enabled bool) deviceAction {
	s.automatic = enabled
	if !enabled && s.stoppedByAuto {
		s.stoppedByAuto = false
		return deviceStart
	}
	if enabled && s.keyPresent {
		s.stoppedByAuto = true
		return deviceStop
	}
	return deviceNone
}

func (s *autoSwitchState) setKeyPresent(present bool) deviceAction {
	if s.keyPresent == present {
		return deviceNone
	}
	s.keyPresent = present
	if !s.automatic {
		return deviceNone
	}
	if present {
		s.stoppedByAuto = true
		return deviceStop
	}
	if s.stoppedByAuto {
		s.stoppedByAuto = false
		return deviceStart
	}
	return deviceNone
}
