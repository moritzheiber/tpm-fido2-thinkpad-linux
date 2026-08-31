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

// recorder collects notifications safely across goroutines.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) notify(title, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, body)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.msgs))
	copy(out, r.msgs)
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
	rec := &recorder{}
	fake := &fakeVerifier{
		closedCh: make(chan struct{}),
		verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
			if username != "" {
				t.Errorf("expected empty username (calling user), got %q", username)
			}
			return nil
		},
	}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) { return fake, nil },
		notify:      rec.notify,
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("expected OK, got error %v", r.Error)
	}
	if len(rec.all()) == 0 {
		t.Error("expected an initial prompt notification")
	}
	select {
	case <-fake.closedCh:
	case <-time.After(2 * time.Second):
		t.Error("expected the verifier to be closed")
	}
}

func TestConfirmPresenceFailure(t *testing.T) {
	rec := &recorder{}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				return errors.New("boom")
			}}, nil
		},
		notify: rec.notify,
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
	rec := &recorder{}
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				onRetry("Fingerprint not recognized. Touch the sensor again.")
				return nil
			}}, nil
		},
		notify: rec.notify,
	}

	ch, err := up.ConfirmPresence("Register", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatalf("ConfirmPresence: %v", err)
	}
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("expected OK, got %v", r.Error)
	}

	found := false
	for _, m := range rec.all() {
		if m == "Fingerprint not recognized. Touch the sensor again." {
			found = true
		}
	}
	if !found {
		t.Errorf("expected retry hint in notifications, got %v", rec.all())
	}
}

func TestConfirmPresenceVerifierInitError(t *testing.T) {
	up := &UserPresence{
		newVerifier: func() (Verifier, error) { return nil, errors.New("no bus") },
		notify:      func(string, string) {},
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

func TestConfirmPresenceRejectsConcurrentDifferentRequest(t *testing.T) {
	release := make(chan struct{})
	up := &UserPresence{
		newVerifier: func() (Verifier, error) {
			return &fakeVerifier{verifyFunc: func(ctx context.Context, username string, onRetry func(string)) error {
				<-release
				return nil
			}}, nil
		},
		notify: func(string, string) {},
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
