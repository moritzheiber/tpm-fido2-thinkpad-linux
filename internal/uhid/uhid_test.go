//go:build linux

package uhid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testConfig() Config {
	return Config{Name: "test-key", Bus: 3, VendorID: 0x1209, ProductID: 0xf1d0, Descriptor: []byte{0x05, 0x01}}
}

func packet(kind uint32, size int) []byte {
	buf := make([]byte, size)
	binary.NativeEndian.PutUint32(buf, kind)
	return buf
}

func socketPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	device := os.NewFile(uintptr(fds[0]), "uhid-test-device")
	kernel := os.NewFile(uintptr(fds[1]), "uhid-test-kernel")
	t.Cleanup(func() {
		device.Close()
		kernel.Close()
	})
	if err := kernel.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return device, kernel
}

func testDevice(t *testing.T) (*Device, *os.File) {
	t.Helper()
	file, kernel := socketPair(t)
	server := make(chan error, 1)
	go func() {
		_, err := kernel.Read(make([]byte, 4380))
		if err == nil {
			_, err = kernel.Write(packet(2, 4))
		}
		server <- err
	}()
	device, err := open(context.Background(), testConfig(), func() (deviceFile, error) { return file, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := <-server; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close() })
	return device, kernel
}

func TestCreateWireFormat(t *testing.T) {
	buf, err := encodeCreate(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 282 || binary.NativeEndian.Uint32(buf[:4]) != 11 {
		t.Fatalf("invalid CREATE2 type or size: size=%d", len(buf))
	}
	if string(bytes.TrimRight(buf[4:132], "\x00")) != "test-key" {
		t.Error("incorrect device name")
	}
	if binary.NativeEndian.Uint16(buf[260:262]) != 2 || binary.NativeEndian.Uint16(buf[262:264]) != 3 {
		t.Error("incorrect descriptor length or bus")
	}
	if binary.NativeEndian.Uint32(buf[264:268]) != 0x1209 || binary.NativeEndian.Uint32(buf[268:272]) != 0xf1d0 {
		t.Error("incorrect vendor or product")
	}
	if !bytes.Equal(buf[280:], testConfig().Descriptor) {
		t.Error("incorrect descriptor offset")
	}
}

func TestInvalidConfigDoesNotOpenFile(t *testing.T) {
	for _, cfg := range []Config{
		{Descriptor: []byte{1}},
		{Name: "key"},
		{Name: strings.Repeat("x", 128), Descriptor: []byte{1}},
		{Name: "bad\x00name", Descriptor: []byte{1}},
		{Name: "key", Descriptor: make([]byte, 4097)},
	} {
		opened := false
		_, err := open(context.Background(), cfg, func() (deviceFile, error) {
			opened = true
			return nil, errors.New("unexpected open")
		})
		if err == nil || opened {
			t.Fatalf("invalid config: error=%v opened=%v", err, opened)
		}
	}
}

type faultFile struct {
	reader   io.Reader
	writeErr error
	short    bool
	closeErr error
	closes   int
}

func (f *faultFile) Read(b []byte) (int, error) {
	if f.reader == nil {
		return 0, io.EOF
	}
	return f.reader.Read(b)
}
func (f *faultFile) Write(b []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (f *faultFile) SetReadDeadline(time.Time) error { return nil }
func (f *faultFile) Close() error {
	f.closes++
	return f.closeErr
}

func TestFailedStartupClosesFile(t *testing.T) {
	writeErr := errors.New("create rejected")
	closeErr := errors.New("close failed")
	for name, file := range map[string]*faultFile{
		"write":         {writeErr: writeErr},
		"short write":   {short: true},
		"EOF":           {},
		"unexpected":    {reader: bytes.NewReader(packet(4, 4))},
		"close failure": {writeErr: writeErr, closeErr: closeErr},
	} {
		t.Run(name, func(t *testing.T) {
			device, err := open(context.Background(), testConfig(), func() (deviceFile, error) { return file, nil })
			if device != nil || err == nil || file.closes != 1 {
				t.Fatalf("device=%v err=%v closes=%d", device, err, file.closes)
			}
			if file.writeErr != nil && !errors.Is(err, writeErr) {
				t.Errorf("lost write error: %v", err)
			}
			if file.closeErr != nil && !errors.Is(err, closeErr) {
				t.Errorf("lost close error: %v", err)
			}
			if file.short && !errors.Is(err, io.ErrShortWrite) {
				t.Errorf("lost short-write error: %v", err)
			}
		})
	}
}

func TestStartupDeadlineClosesFile(t *testing.T) {
	file, _ := socketPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	device, err := open(ctx, testConfig(), func() (deviceFile, error) { return file, nil })
	if device != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("device=%v err=%v", device, err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("startup left descriptor open: %v", err)
	}
}

func TestReadCancellationAndSubsequentRead(t *testing.T) {
	device, kernel := testDevice(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := device.Read(ctx)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read did not return")
	}
	if _, err := kernel.Write(packet(4, 4)); err != nil {
		t.Fatal(err)
	}
	ev, err := device.Read(context.Background())
	if err != nil || ev.Type != Opened {
		t.Fatalf("next read: event=%v err=%v", ev, err)
	}
}

func TestCloseInterruptsReadAndIsIdempotent(t *testing.T) {
	device, _ := testDevice(t)
	done := make(chan error, 1)
	go func() {
		_, err := device.Read(context.Background())
		done <- err
	}()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			if err := device.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
	wg.Wait()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock read")
	}
}

func TestOutputUsesReportedLength(t *testing.T) {
	device, kernel := testDevice(t)
	buf := packet(6, 4103)
	copy(buf[4:], []byte{0, 1, 2, 3})
	binary.NativeEndian.PutUint16(buf[4100:], 4)
	buf[4102] = 1
	if _, err := kernel.Write(buf); err != nil {
		t.Fatal(err)
	}
	ev, err := device.Read(context.Background())
	if err != nil || ev.Type != Output || !bytes.Equal(ev.Data, []byte{0, 1, 2, 3}) {
		t.Fatalf("event=%v err=%v", ev, err)
	}
	binary.NativeEndian.PutUint16(buf[4100:], 4097)
	if _, err := kernel.Write(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := device.Read(context.Background()); err == nil {
		t.Fatal("accepted oversized output")
	}
}

func TestInputWireFormatAndBounds(t *testing.T) {
	device, kernel := testDevice(t)
	if err := device.WriteInput([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4380)
	n, err := kernel.Read(buf)
	if err != nil || n != 9 || binary.NativeEndian.Uint32(buf[:4]) != 12 ||
		binary.NativeEndian.Uint16(buf[4:6]) != 3 || !bytes.Equal(buf[6:n], []byte{1, 2, 3}) {
		t.Fatalf("INPUT2: size=%d data=%x err=%v", n, buf[:n], err)
	}
	if err := device.WriteInput(make([]byte, 4097)); err == nil {
		t.Error("accepted oversized input")
	}
}

func TestControlRequestsReceiveErrorReplies(t *testing.T) {
	for _, kind := range []uint32{9, 13} {
		t.Run(strconv.FormatUint(uint64(kind), 10), func(t *testing.T) {
			device, kernel := testDevice(t)
			request := packet(kind, 12)
			binary.NativeEndian.PutUint32(request[4:], 123)
			if _, err := kernel.Write(request); err != nil {
				t.Fatal(err)
			}
			if _, err := kernel.Write(packet(4, 4)); err != nil {
				t.Fatal(err)
			}
			if _, err := device.Read(context.Background()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4380)
			n, err := kernel.Read(buf)
			if err != nil || n < 10 || binary.NativeEndian.Uint32(buf) != kind+1 ||
				binary.NativeEndian.Uint32(buf[4:]) != 123 || binary.NativeEndian.Uint16(buf[8:]) != uint16(unix.EIO) {
				t.Fatalf("control reply: size=%d err=%v", n, err)
			}
		})
	}
}

func TestRepeatedLifecycleDoesNotRetainResources(t *testing.T) {
	warmup, _ := testDevice(t)
	warmup.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	goroutines := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		device, kernel := testDevice(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			device.Read(ctx)
			close(done)
		}()
		cancel()
		<-done
		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
		kernel.Close()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || runtime.NumGoroutine() > goroutines {
		t.Fatalf("fds %d -> %d, goroutines %d -> %d", len(before), len(after), goroutines, runtime.NumGoroutine())
	}
}
