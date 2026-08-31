package userpresence

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/fprintd"
)

// Verifier performs a fingerprint verification against the fingerprint daemon.
// It blocks until the user is verified, ctx is done, or an error occurs.
// onRetry, if non-nil, is called with a short hint whenever the user should try
// again. Implemented by *fprintd.Client; abstracted here for testing.
type Verifier interface {
	Verify(ctx context.Context, username string, onRetry func(hint string)) error
	Close() error
}

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request

	// newVerifier creates a Verifier for a single confirmation. Overridable in
	// tests; defaults to a fprintd D-Bus client.
	newVerifier func() (Verifier, error)
	// notify surfaces a desktop notification. Overridable in tests.
	notify func(title, body string)
}

type request struct {
	timeout          time.Duration
	pendingResult    chan Result
	extendTimeout    chan time.Duration
	challengeParam   [32]byte
	applicationParam [32]byte
}

// Result represents the outcome of a user presence check
type Result struct {
	OK    bool
	Error error
}

// New creates a new UserPresence handler
func New() *UserPresence {
	return &UserPresence{
		newVerifier: func() (Verifier, error) {
			return fprintd.New()
		},
		notify: notifySend,
	}
}

// ConfirmPresence requests user presence confirmation via fingerprint
func (up *UserPresence) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	timeout := 30 * time.Second

	if up.activeRequest != nil {
		if challengeParam != up.activeRequest.challengeParam || applicationParam != up.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := up.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(2 * time.Second):
			}
		}()

		return up.activeRequest.pendingResult, nil
	}

	up.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go up.promptFingerprint(up.activeRequest, prompt)

	return up.activeRequest.pendingResult, nil
}

func (up *UserPresence) promptFingerprint(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(2 * time.Second):
			// Client likely gone
		}

		up.mu.Lock()
		up.activeRequest = nil
		up.mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.timeout)
	defer cancel()

	log.Printf("userpresence: prompt=%s", prompt)
	up.notify("TPM-FIDO", prompt+"\n\nTouch fingerprint sensor to confirm.")

	verifier, err := up.newVerifier()
	if err != nil {
		log.Printf("userpresence: fingerprint daemon unavailable: %v", err)
		sendResult(Result{OK: false, Error: err})
		return
	}
	defer verifier.Close()

	onRetry := func(hint string) {
		log.Printf("userpresence: %s", hint)
		up.notify("TPM-FIDO", hint)
	}

	// Empty username verifies against the calling user's enrolled fingers.
	err = verifier.Verify(ctx, "", onRetry)
	if err != nil {
		log.Printf("userpresence: fingerprint verification failed: %v", err)
		if errors.Is(err, context.DeadlineExceeded) {
			sendResult(Result{OK: false, Error: errors.New("fingerprint verification timed out")})
		} else {
			sendResult(Result{OK: false, Error: err})
		}
		return
	}

	log.Printf("userpresence: fingerprint verified successfully")
	sendResult(Result{OK: true, Error: nil})
}

// notifySend shows a desktop notification via notify-send. The
// x-canonical-private-synchronous hint collapses tpm-fido notifications into a
// single slot, so retry hints replace the prompt instead of stacking.
func notifySend(title, body string) {
	cmd := exec.Command("notify-send",
		"-u", "critical",
		"-t", "30000",
		"-h", "string:x-canonical-private-synchronous:tpm-fido",
		title, body)
	if err := cmd.Start(); err != nil {
		log.Printf("userpresence: notify-send failed to start: %v", err)
		return
	}
	// Reap the process so it does not become a zombie.
	go cmd.Wait()
}
