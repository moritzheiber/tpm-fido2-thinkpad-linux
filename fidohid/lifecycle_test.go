package fidohid

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/internal/uhid"
)

type fakeTransport struct {
	events   chan uhid.Event
	readErr  error
	closeErr error
	closes   atomic.Int32
}

func (f *fakeTransport) Read(ctx context.Context) (uhid.Event, error) {
	if f.readErr != nil {
		return uhid.Event{}, f.readErr
	}
	select {
	case <-ctx.Done():
		return uhid.Event{}, ctx.Err()
	case ev := <-f.events:
		return ev, nil
	}
}
func (f *fakeTransport) WriteInput([]byte) error { return nil }
func (f *fakeTransport) Close() error {
	f.closes.Add(1)
	return f.closeErr
}

func await(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("lifecycle operation did not complete")
		return nil
	}
}

func TestCloseDuringStartupCancelsOpen(t *testing.T) {
	started := make(chan struct{})
	device, err := New("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	device.open = func(ctx context.Context) (hidTransport, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { result <- device.Run(context.Background()) }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- device.Close() }()
	if err := await(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
}

func TestCloseBeforeRunPreventsOpening(t *testing.T) {
	device, err := New("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := false
	device.open = func(context.Context) (hidTransport, error) {
		opened = true
		return &fakeTransport{}, nil
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if err := device.Run(context.Background()); err == nil || opened {
		t.Fatalf("Run error=%v opened=%v", err, opened)
	}
}

func TestFailedOpenDoesNotCloseTypedNilTransport(t *testing.T) {
	device, err := New("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	device.open = func(context.Context) (hidTransport, error) {
		var transport *uhid.Device
		return transport, context.Canceled
	}
	if err := device.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadFailureClosesTransportOnce(t *testing.T) {
	readErr := errors.New("reader failed")
	closeErr := errors.New("close failed")
	transport := &fakeTransport{readErr: readErr, closeErr: closeErr}
	device, err := New("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	device.open = func(context.Context) (hidTransport, error) { return transport, nil }
	err = device.Run(context.Background())
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("Run did not propagate errors: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := device.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close lost cleanup error: %v", err)
		}
	}
	if transport.closes.Load() != 1 {
		t.Fatalf("transport closed %d times", transport.closes.Load())
	}
}

type blockingHandler struct {
	started chan struct{}
	stopped chan struct{}
}

func (h blockingHandler) HandleCommand(ctx context.Context, _ byte, _ []byte) (byte, []byte) {
	close(h.started)
	<-ctx.Done()
	close(h.stopped)
	return 0, nil
}

func TestCloseWaitsForCommandWorkers(t *testing.T) {
	handler := blockingHandler{started: make(chan struct{}), stopped: make(chan struct{})}
	transport := &fakeTransport{events: make(chan uhid.Event, 1)}
	device, err := New("test", handler)
	if err != nil {
		t.Fatal(err)
	}
	device.open = func(context.Context) (hidTransport, error) { return transport, nil }
	packet := make([]byte, reportLen)
	binary.BigEndian.PutUint32(packet, 0x01000001)
	packet[4] = cmdCBOR | 0x80
	binary.BigEndian.PutUint16(packet[5:], 1)
	packet[7] = 4
	transport.events <- uhid.Event{Type: uhid.Output, Data: packet}
	result := make(chan error, 1)
	go func() { result <- device.Run(context.Background()) }()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("command did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- device.Close() }()
	if err := await(t, closed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.stopped:
	default:
		t.Fatal("Close returned before worker stopped")
	}
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}
	if transport.closes.Load() != 1 {
		t.Fatalf("transport closed %d times", transport.closes.Load())
	}
}
