package userpresence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeVerifier is a scripted Verifier for testing.
type fakeVerifier struct {
	verifyFunc func(ctx context.Context, username string, onRetry func(hint string)) error
	closedCh   chan struct{}
	closeOnce  sync.Once
}

func (f *fakeVerifier) Verify(ctx context.Context, username string, onRetry func(hint string)) error {
	return f.verifyFunc(ctx, username, onRetry)
}

func (f *fakeVerifier) Close() error {
	if f.closedCh != nil {
		f.closeOnce.Do(func() { close(f.closedCh) })
	}
	return nil
}

type notification struct {
	title string
	body  string
}

type fakeNotifier struct {
	mu        sync.Mutex
	shown     []notification
	showError error
	closedCh  chan struct{}
	closeOnce sync.Once
}

func (f *fakeNotifier) Show(_ context.Context, title, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = append(f.shown, notification{title: title, body: body})
	return f.showError
}

func (f *fakeNotifier) Close() error {
	if f.closedCh != nil {
		f.closeOnce.Do(func() { close(f.closedCh) })
	}
	return nil
}

func (f *fakeNotifier) all() []notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]notification, len(f.shown))
	copy(out, f.shown)
	return out
}

func waitResult(t *testing.T, ch chan Result) Result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for presence result")
		return Result{}
	}
}

func TestConfirmPresenceSuccess(t *testing.T) {
	fake := &fakeVerifier{
		closedCh: make(chan struct{}),
		verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
			if username != "" {
				t.Errorf("expected empty username (calling user), got %q", username)
			}
			return nil
		},
	}
	notifier := &fakeNotifier{closedCh: make(chan struct{})}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) { return fake, nil },
		newNotifier: func() (Notifier, error) { return notifier, nil },
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("expected OK, got error %v", r.Error)
	}
	if len(notifier.all()) == 0 {
		t.Error("expected an initial prompt notification")
	}
	select {
	case <-fake.closedCh:
	case <-time.After(2 * time.Second):
		t.Error("expected the verifier to be closed")
	}
	select {
	case <-notifier.closedCh:
	case <-time.After(2 * time.Second):
		t.Error("expected the notifier to be closed")
	}
}

func TestConfirmPresenceFailure(t *testing.T) {
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				return errors.New("boom")
			}}, nil
		},
		newNotifier: func() (Notifier, error) { return &fakeNotifier{}, nil },
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	r := waitResult(t, ch)
	if r.OK {
		t.Fatal("expected failure, got OK")
	}
	if r.Error == nil {
		t.Fatal("expected an error on failure")
	}
}

func TestConfirmPresenceRetryNotifies(t *testing.T) {
	notifier := &fakeNotifier{}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				onRetry("Fingerprint not recognized. Touch the sensor again.")
				return nil
			}}, nil
		},
		newNotifier: func() (Notifier, error) { return notifier, nil },
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("expected OK, got %v", r.Error)
	}

	found := false
	for _, n := range notifier.all() {
		if n.body == "Fingerprint not recognized. Touch the sensor again." {
			found = true
		}
	}
	if !found {
		t.Errorf("expected retry hint in notifications, got %v", notifier.all())
	}
}

func TestConfirmPresenceVerifierInitError(t *testing.T) {
	up := &UserPresence{
		newVerifier: func() (Verifier, error) { return nil, errors.New("no bus") },
		newNotifier: func() (Notifier, error) { return &fakeNotifier{}, nil },
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	r := waitResult(t, ch)
	if r.OK || r.Error == nil {
		t.Fatalf("expected failure when verifier cannot be created, got OK=%v err=%v", r.OK, r.Error)
	}
}

func TestConfirmPresenceContinuesWithoutNotificationService(t *testing.T) {
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(context.Context, string, func(string)) error {
				return nil
			}}, nil
		},
		newNotifier: func() (Notifier, error) {
			return nil, errors.New("no notification service")
		},
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("notification service failure blocked verification: %v", r.Error)
	}
}

func TestConfirmPresenceContinuesWhenNotificationFails(t *testing.T) {
	notifier := &fakeNotifier{showError: errors.New("notify failed")}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(context.Context, string, func(string)) error {
				return nil
			}}, nil
		},
		newNotifier: func() (Notifier, error) { return notifier, nil },
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("notification failure blocked verification: %v", r.Error)
	}
}

func TestConfirmPresenceRejectsConcurrentDifferentRequest(t *testing.T) {
	release := make(chan struct{})
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				<-release
				return nil
			}}, nil
		},
		newNotifier: func() (Notifier, error) { return &fakeNotifier{}, nil },
	}

	ch1, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("first ConfirmPresence: %v", err)
	}

	// A different challenge/app while one is in flight must be rejected.
	if _, err := up.ConfirmPresence("Register", [32]byte{9}, [32]byte{9}); err == nil {
		t.Error("expected error for a concurrent different request")
	}

	close(release)
	if r := waitResult(t, ch1); !r.OK {
		t.Fatalf("expected first request to succeed, got %v", r.Error)
	}
}
