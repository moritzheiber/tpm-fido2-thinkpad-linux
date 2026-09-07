package userpresence

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/desktopnotify"
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

// Notifier owns a replaceable desktop notification for one confirmation.
type Notifier interface {
	Show(ctx context.Context, title, body string) error
	Close() error
}

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request

	// newVerifier creates a Verifier for a single confirmation. Overridable in
	// tests; defaults to a fprintd D-Bus client.
	newVerifier func() (Verifier, error)
	// newNotifier creates one replaceable desktop notification. Overridable in
	// tests; defaults to an org.freedesktop.Notifications D-Bus client.
	newNotifier func() (Notifier, error)

	requestTimeout time.Duration
}

type request struct {
	timeout          time.Duration
	waiters          []chan Result
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
		newNotifier: func() (Notifier, error) {
			return desktopnotify.New()
		},
		requestTimeout: 30 * time.Second,
	}
}

// ConfirmPresence requests user presence confirmation via fingerprint
func (up *UserPresence) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	timeout := up.requestTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if up.activeRequest != nil {
		if challengeParam != up.activeRequest.challengeParam || applicationParam != up.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		result := make(chan Result, 1)
		up.activeRequest.waiters = append(up.activeRequest.waiters, result)
		select {
		case <-up.activeRequest.extendTimeout:
		default:
		}
		up.activeRequest.extendTimeout <- timeout
		return result, nil
	}

	result := make(chan Result, 1)
	up.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		waiters:          []chan Result{result},
		extendTimeout:    make(chan time.Duration, 1),
	}

	go up.promptFingerprint(up.activeRequest, prompt)

	return result, nil
}

func (up *UserPresence) promptFingerprint(req *request, prompt string) {
	sendResult := func(r Result) {
		up.mu.Lock()
		if up.activeRequest == req {
			up.activeRequest = nil
		}
		waiters := append([]chan Result(nil), req.waiters...)
		up.mu.Unlock()
		for _, waiter := range waiters {
			waiter <- r
			close(waiter)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("userpresence: prompt=%s", prompt)

	notifier, err := up.newNotifier()
	if err != nil {
		log.Printf("userpresence: desktop notifications unavailable: %v", err)
	} else {
		defer func() {
			if err := notifier.Close(); err != nil {
				log.Printf("userpresence: close desktop notification: %v", err)
			}
		}()
		if err := notifier.Show(ctx, "TPM-FIDO", prompt+"\n\nTouch fingerprint sensor to confirm."); err != nil {
			log.Printf("userpresence: show desktop notification: %v", err)
		}
	}

	verifier, err := up.newVerifier()
	if err != nil {
		log.Printf("userpresence: fingerprint daemon unavailable: %v", err)
		sendResult(Result{OK: false, Error: err})
		return
	}
	defer func() {
		if err := verifier.Close(); err != nil {
			log.Printf("userpresence: close fingerprint verifier: %v", err)
		}
	}()

	onRetry := func(hint string) {
		log.Printf("userpresence: %s", hint)
		if notifier != nil {
			if err := notifier.Show(ctx, "TPM-FIDO", hint); err != nil {
				log.Printf("userpresence: update desktop notification: %v", err)
			}
		}
	}

	verification := make(chan error, 1)
	go func() {
		// Empty username verifies against the calling user's enrolled fingers.
		verification <- verifier.Verify(ctx, "", onRetry)
	}()

	timer := time.NewTimer(req.timeout)
	defer timer.Stop()
	for {
		select {
		case err = <-verification:
			if err != nil {
				log.Printf("userpresence: fingerprint verification failed: %v", err)
				sendResult(Result{OK: false, Error: err})
				return
			}
			log.Printf("userpresence: fingerprint verified successfully")
			sendResult(Result{OK: true})
			return
		case timeout := <-req.extendTimeout:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		case <-timer.C:
			cancel()
			if cleanupErr := <-verification; cleanupErr != nil && !errors.Is(cleanupErr, context.Canceled) {
				log.Printf("userpresence: fingerprint verification cleanup after timeout: %v", cleanupErr)
			}
			sendResult(Result{OK: false, Error: errors.New("fingerprint verification timed out")})
			return
		}
	}
}
