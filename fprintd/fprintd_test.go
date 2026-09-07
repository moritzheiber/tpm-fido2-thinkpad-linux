package fprintd

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestClassifyResult(t *testing.T) {
	cases := []struct {
		result      string
		wantOutcome verifyOutcome
		wantHint    bool
	}{
		{"verify-match", outcomeMatch, false},
		{"verify-no-match", outcomeNoMatch, false},
		{"verify-retry-scan", outcomeTransient, true},
		{"verify-swipe-too-short", outcomeTransient, true},
		{"verify-finger-not-centered", outcomeTransient, true},
		{"verify-remove-and-retry", outcomeTransient, true},
		{"verify-disconnected", outcomeFatal, true},
		{"verify-unknown-error", outcomeFatal, true},
		{"something-unexpected", outcomeTransient, false},
	}

	for _, tc := range cases {
		gotOutcome, gotHint := classifyResult(tc.result)
		if gotOutcome != tc.wantOutcome {
			t.Errorf("classifyResult(%q) outcome = %d, want %d", tc.result, gotOutcome, tc.wantOutcome)
		}
		if (gotHint != "") != tc.wantHint {
			t.Errorf("classifyResult(%q) hint = %q, wantHint = %v", tc.result, gotHint, tc.wantHint)
		}
	}
}

// step is a single scripted VerifyStatus delivery for the fake session.
type step struct {
	result string
	err    error
}

// fakeSession is a scripted verifySession for testing the retry policy without
// a real fprintd/D-Bus connection.
type fakeSession struct {
	steps      []step
	i          int
	startCount int
	stopCount  int
	stopErr    error
}

func (f *fakeSession) start(ctx context.Context) error {
	f.startCount++
	return nil
}

func (f *fakeSession) stop(context.Context) error {
	f.stopCount++
	return f.stopErr
}

func (f *fakeSession) next(ctx context.Context) (string, error) {
	if f.i < len(f.steps) {
		s := f.steps[f.i]
		f.i++
		return s.result, s.err
	}
	// No more scripted steps: behave like a live stream and block until the
	// context is cancelled.
	<-ctx.Done()
	return "", ctx.Err()
}

func TestVerifyMatchFirstAttempt(t *testing.T) {
	f := &fakeSession{steps: []step{{result: "verify-match"}}}
	retries := 0

	if err := verify(context.Background(), f, func(string) { retries++ }); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if f.startCount != 1 {
		t.Errorf("startCount = %d, want 1", f.startCount)
	}
	if f.stopCount != 1 {
		t.Errorf("stopCount = %d, want 1", f.stopCount)
	}
	if retries != 0 {
		t.Errorf("onRetry called %d times, want 0", retries)
	}
}

func TestVerifyNoMatchThenMatchRestartsAttempt(t *testing.T) {
	f := &fakeSession{steps: []step{
		{result: "verify-no-match"},
		{result: "verify-match"},
	}}
	retries := 0

	if err := verify(context.Background(), f, func(string) { retries++ }); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	// A non-match must trigger a fresh VerifyStart cycle.
	if f.startCount != 2 {
		t.Errorf("startCount = %d, want 2 (retry restarts the attempt)", f.startCount)
	}
	if f.stopCount != 2 {
		t.Errorf("stopCount = %d, want 2", f.stopCount)
	}
	if retries == 0 {
		t.Error("onRetry should be called on a non-match")
	}
}

func TestVerifyTransientDoesNotRestartAttempt(t *testing.T) {
	f := &fakeSession{steps: []step{
		{result: "verify-retry-scan"},
		{result: "verify-match"},
	}}
	var hints []string

	if err := verify(context.Background(), f, func(h string) { hints = append(hints, h) }); err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	// A transient scan problem continues the same attempt, no restart.
	if f.startCount != 1 {
		t.Errorf("startCount = %d, want 1 (transient must not restart)", f.startCount)
	}
	if len(hints) == 0 {
		t.Error("onRetry should receive a hint on a transient scan problem")
	}
}

func TestVerifyFatalReturnsError(t *testing.T) {
	f := &fakeSession{steps: []step{{result: "verify-disconnected"}}}

	err := verify(context.Background(), f, nil)
	if err == nil {
		t.Fatal("verify should return an error on a fatal result")
	}
	if f.stopCount != 1 {
		t.Errorf("stopCount = %d, want 1 (must stop before returning)", f.stopCount)
	}
}

func TestVerifyStreamErrorPropagates(t *testing.T) {
	sentinel := errors.New("stream broke")
	f := &fakeSession{steps: []step{{err: sentinel}}}

	err := verify(context.Background(), f, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("verify error = %v, want %v", err, sentinel)
	}
}

func TestVerifyStopErrorPropagates(t *testing.T) {
	sentinel := errors.New("stop failed")
	f := &fakeSession{steps: []step{{result: "verify-match"}}, stopErr: sentinel}

	if err := verify(context.Background(), f, nil); !errors.Is(err, sentinel) {
		t.Fatalf("verify error = %v, want %v", err, sentinel)
	}
}

func TestVerifyContextCancel(t *testing.T) {
	f := &fakeSession{} // no scripted steps: next blocks on ctx
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := verify(ctx, f, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("verify error = %v, want context.Canceled", err)
	}
	if f.stopCount == 0 {
		t.Error("verify should stop the attempt on cancellation")
	}
}

func TestSignalStreamClosureReturnsError(t *testing.T) {
	signals := make(chan *dbus.Signal)
	close(signals)
	session := &dbusSession{devPath: "/test", sigCh: signals}

	if _, err := session.next(context.Background()); !errors.Is(err, errSignalStreamClosed) {
		t.Fatalf("next error = %v, want %v", err, errSignalStreamClosed)
	}
}

func TestNilSignalReturnsError(t *testing.T) {
	signals := make(chan *dbus.Signal, 1)
	signals <- nil
	session := &dbusSession{devPath: "/test", sigCh: signals}

	if _, err := session.next(context.Background()); !errors.Is(err, errSignalStreamClosed) {
		t.Fatalf("next error = %v, want %v", err, errSignalStreamClosed)
	}
}
