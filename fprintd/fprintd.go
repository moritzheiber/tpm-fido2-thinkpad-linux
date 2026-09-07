// Package fprintd is a small client for the fprintd fingerprint daemon over
// its system-bus D-Bus API (net.reactivated.Fprint).
//
// It talks to fprintd directly instead of shelling out to the fprintd-verify
// example tool. That tool verifies against only the first enrolled finger and
// makes a single attempt; this client verifies against any enrolled finger and
// retries transient scan errors and non-matches until a match, the context is
// cancelled, or an unrecoverable error occurs.
package fprintd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName      = "net.reactivated.Fprint"
	managerPath  = dbus.ObjectPath("/net/reactivated/Fprint/Manager")
	managerIface = "net.reactivated.Fprint.Manager"
	deviceIface  = "net.reactivated.Fprint.Device"

	// anyFinger asks fprintd to match against every enrolled finger. On press
	// (match-on-chip) devices this is the correct way to accept any finger.
	anyFinger = "any"

	sigVerifyStatus = deviceIface + ".VerifyStatus"

	noMatchHint    = "Fingerprint not recognized. Touch the sensor again."
	cleanupTimeout = 2 * time.Second
)

// ErrNoDevice is returned when fprintd reports no fingerprint device.
var ErrNoDevice = errors.New("no fingerprint device available")
var errSignalStreamClosed = errors.New("fprintd signal stream closed")

type verifyOutcome int

const (
	outcomeMatch verifyOutcome = iota
	outcomeNoMatch
	outcomeTransient
	outcomeFatal
)

// classifyResult maps a fprintd VerifyStatus result string to an outcome and a
// human-readable hint. For transient outcomes the hint tells the user how to
// retry; for fatal outcomes the hint is the error message.
func classifyResult(result string) (verifyOutcome, string) {
	switch result {
	case "verify-match":
		return outcomeMatch, ""
	case "verify-no-match":
		return outcomeNoMatch, ""
	case "verify-retry-scan":
		return outcomeTransient, "Keep your finger on the sensor."
	case "verify-swipe-too-short":
		return outcomeTransient, "Swipe was too short. Try again."
	case "verify-finger-not-centered":
		return outcomeTransient, "Center your finger and try again."
	case "verify-remove-and-retry":
		return outcomeTransient, "Remove your finger and touch the sensor again."
	case "verify-disconnected":
		return outcomeFatal, "fingerprint device disconnected"
	case "verify-unknown-error":
		return outcomeFatal, "fingerprint verification error"
	default:
		return outcomeTransient, ""
	}
}

// verifySession is one claimed device session. It abstracts the fprintd D-Bus
// device so the retry policy can be tested without a real bus.
type verifySession interface {
	// start begins a verification attempt (VerifyStart "any").
	start(ctx context.Context) error
	// stop ends the current attempt (VerifyStop).
	stop(context.Context) error
	// next returns the next VerifyStatus result string, or an error if the
	// context is done or the stream fails.
	next(ctx context.Context) (string, error)
}

// verify drives a claimed session until a match, context cancellation, or a
// fatal error. It retries transient scan problems within an attempt and
// restarts the attempt on a non-match. onRetry, if non-nil, receives a short
// hint whenever the user should try again.
func verify(ctx context.Context, s verifySession, onRetry func(hint string)) error {
	for {
		if err := s.start(ctx); err != nil {
			return fmt.Errorf("verify start: %w", err)
		}
		matched, retry, err := attempt(ctx, s, onRetry)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		stopErr := s.stop(cleanupCtx)
		cancel()
		if err := errors.Join(err, stopErr); err != nil {
			return err
		}
		if matched {
			return nil
		}
		if retry && onRetry != nil {
			onRetry(noMatchHint)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// attempt consumes status results for a single VerifyStart cycle. It returns
// matched=true on a match, retry=true on a completed non-match, or an error for
// a fatal condition or context cancellation.
func attempt(ctx context.Context, s verifySession, onRetry func(hint string)) (matched, retry bool, err error) {
	for {
		result, err := s.next(ctx)
		if err != nil {
			return false, false, err
		}
		outcome, hint := classifyResult(result)
		switch outcome {
		case outcomeMatch:
			return true, false, nil
		case outcomeNoMatch:
			return false, true, nil
		case outcomeTransient:
			if onRetry != nil && hint != "" {
				onRetry(hint)
			}
		case outcomeFatal:
			return false, false, errors.New(hint)
		}
	}
}

// Client is a connection to fprintd on the system bus.
type Client struct {
	conn *dbus.Conn
}

// New connects to fprintd on the system bus.
func New() (*Client, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect system bus: %w", err)
	}
	return &Client{conn: conn}, nil
}

// Close closes the underlying bus connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Verify claims the default fingerprint device for username (empty string means
// the calling user), then verifies against any enrolled finger, retrying until a
// match, ctx is done, or an unrecoverable error occurs. onRetry, if non-nil, is
// called with a short hint whenever the user should try again.
func (c *Client) Verify(ctx context.Context, username string, onRetry func(hint string)) (err error) {
	var devPath dbus.ObjectPath
	manager := c.conn.Object(busName, managerPath)
	if err := manager.CallWithContext(ctx, managerIface+".GetDefaultDevice", 0).Store(&devPath); err != nil {
		return fmt.Errorf("get default device: %w", err)
	}
	if devPath == "" || devPath == "/" {
		return ErrNoDevice
	}

	dev := c.conn.Object(busName, devPath)

	if call := dev.CallWithContext(ctx, deviceIface+".Claim", 0, username); call.Err != nil {
		return fmt.Errorf("claim device: %w", call.Err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if call := dev.CallWithContext(cleanupCtx, deviceIface+".Release", 0); call.Err != nil {
			err = errors.Join(err, fmt.Errorf("release fingerprint device: %w", call.Err))
		}
	}()

	matchOpts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(devPath),
		dbus.WithMatchInterface(deviceIface),
	}
	if err := c.conn.AddMatchSignalContext(ctx, matchOpts...); err != nil {
		return fmt.Errorf("subscribe to fprintd signals: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if removeErr := c.conn.RemoveMatchSignalContext(cleanupCtx, matchOpts...); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("unsubscribe from fprintd signals: %w", removeErr))
		}
	}()

	sigCh := make(chan *dbus.Signal, 16)
	c.conn.Signal(sigCh)
	defer c.conn.RemoveSignal(sigCh)

	session := &dbusSession{dev: dev, devPath: devPath, sigCh: sigCh}
	return verify(ctx, session, onRetry)
}

// dbusSession implements verifySession against a claimed fprintd device.
type dbusSession struct {
	dev     dbus.BusObject
	devPath dbus.ObjectPath
	sigCh   <-chan *dbus.Signal
}

func (s *dbusSession) start(ctx context.Context) error {
	if call := s.dev.CallWithContext(ctx, deviceIface+".VerifyStart", 0, anyFinger); call.Err != nil {
		return call.Err
	}
	return nil
}

func (s *dbusSession) stop(ctx context.Context) error {
	if call := s.dev.CallWithContext(ctx, deviceIface+".VerifyStop", 0); call.Err != nil {
		return fmt.Errorf("verify stop: %w", call.Err)
	}
	return nil
}

func (s *dbusSession) next(ctx context.Context) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case sig, ok := <-s.sigCh:
			if !ok || sig == nil {
				return "", errSignalStreamClosed
			}
			if sig.Path != s.devPath {
				continue
			}
			if sig.Name != sigVerifyStatus || len(sig.Body) != 2 {
				continue
			}
			result, _ := sig.Body[0].(string)
			return result, nil
		}
	}
}
