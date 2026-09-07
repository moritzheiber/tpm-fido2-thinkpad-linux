//go:build linux && uhid

package fidohid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/moritzheiber/tpm-fido2-thinkpad-linux/ctap2"
	"golang.org/x/sys/unix"
)

func startHardwareDevice(t *testing.T, name string) (*Device, context.CancelFunc, <-chan error, <-chan struct{}) {
	t.Helper()
	device, err := New(name, ctap2.NewHandler(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	open := device.open
	device.open = func(ctx context.Context) (hidTransport, error) {
		transport, err := open(ctx)
		if err == nil {
			close(ready)
		}
		return transport, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- device.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := device.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return device, cancel, done, ready
}

func waitHardwareReady(t *testing.T, ready <-chan struct{}, done <-chan error) {
	t.Helper()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("UHID startup: %v", err)
	case <-time.After(4 * time.Second):
		t.Fatal("UHID startup did not complete")
	}
}

func openTestHidraw(t *testing.T, name string) *os.File {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var lastErr error
	for {
		paths, err := filepath.Glob("/sys/class/hidraw/hidraw*/device/uevent")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), "\nHID_NAME="+name+"\n") {
				continue
			}
			node := filepath.Base(filepath.Dir(filepath.Dir(path)))
			file, err := os.OpenFile(filepath.Join("/dev", node), os.O_RDWR|unix.O_NONBLOCK, 0)
			if err != nil {
				lastErr = err
				continue
			}
			t.Cleanup(func() { file.Close() })
			if err := file.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			return file
		}
		select {
		case <-timeout.C:
			t.Fatalf("test hidraw device unavailable: %v", lastErr)
		case <-tick.C:
		}
	}
}

func hidExchange(t *testing.T, file *os.File, cid uint32, cmd byte, payload []byte) []byte {
	t.Helper()
	packet := make([]byte, reportLen+1)
	binary.BigEndian.PutUint32(packet[1:], cid)
	packet[5] = cmd | 0x80
	binary.BigEndian.PutUint16(packet[6:], uint16(len(payload)))
	copy(packet[8:], payload)
	if _, err := file.Write(packet); err != nil {
		t.Fatal(err)
	}
	var response []byte
	length := -1
	sequence := byte(0)
	for length < 0 || len(response) < length {
		report := make([]byte, reportLen)
		n, err := file.Read(report)
		if err != nil {
			t.Fatalf("read HID response: %v", err)
		}
		if n != reportLen {
			t.Fatalf("HID response length=%d", n)
		}
		if binary.BigEndian.Uint32(report) != cid {
			continue
		}
		if length < 0 {
			if report[4] != cmd|0x80 {
				t.Fatalf("unexpected HID command %#x", report[4])
			}
			length = int(binary.BigEndian.Uint16(report[5:]))
			response = append(response, report[7:]...)
		} else {
			if report[4] != sequence {
				t.Fatalf("continuation sequence=%d, want %d", report[4], sequence)
			}
			sequence++
			response = append(response, report[5:]...)
		}
	}
	return response[:length]
}

func TestUHIDProtocolRoundTrip(t *testing.T) {
	name := fmt.Sprintf("tpm-fido-protocol-test-%d", os.Getpid())
	_, cancel, done, ready := startHardwareDevice(t, name)
	waitHardwareReady(t, ready, done)
	file := openTestHidraw(t, name)
	nonce := []byte("test-key")
	response := hidExchange(t, file, broadcastCID, cmdInit, nonce)
	if len(response) != 17 || !bytes.Equal(response[:8], nonce) {
		t.Fatal("invalid CTAPHID_INIT response")
	}
	cid := binary.BigEndian.Uint32(response[8:12])
	if cid == 0 || cid == broadcastCID {
		t.Fatalf("invalid assigned channel %x", cid)
	}
	ping := []byte("ping")
	if got := hidExchange(t, file, cid, cmdPing, ping); !bytes.Equal(got, ping) {
		t.Fatal("CTAPHID_PING did not echo payload")
	}
	response = hidExchange(t, file, cid, cmdCBOR, []byte{ctap2.CmdGetInfo})
	if len(response) == 0 || response[0] != ctap2.StatusSuccess {
		t.Fatal("GetInfo failed")
	}
	var info ctap2.GetInfoResponse
	if err := cbor.Unmarshal(response[1:], &info); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(info.Versions, "FIDO_2_0") {
		t.Errorf("invalid GetInfo versions: %v", info.Versions)
	}
	file.Close()
	cancel()
	if err := await(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestUHIDRepeatedLifecycle(t *testing.T) {
	name := fmt.Sprintf("tpm-fido-lifetime-test-%d", os.Getpid())
	warmup, cancel, done, ready := startHardwareDevice(t, name)
	waitHardwareReady(t, ready, done)
	cancel()
	await(t, done)
	if err := warmup.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	beforeFD, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	beforeG := runtime.NumGoroutine()
	for i := 0; i < 24; i++ {
		device, cancel, done, ready := startHardwareDevice(t, name)
		if i%4 != 0 {
			waitHardwareReady(t, ready, done)
		}
		cancel()
		if err := await(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	afterFD, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	afterG := runtime.NumGoroutine()
	t.Logf("24 cycles: descriptors %d -> %d; goroutines %d -> %d", len(beforeFD), len(afterFD), beforeG, afterG)
	if len(afterFD) != len(beforeFD) || afterG > beforeG {
		t.Fatal("resources retained after device cycles")
	}
}
