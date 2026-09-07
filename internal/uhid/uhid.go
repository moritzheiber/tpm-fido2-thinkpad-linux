//go:build linux

// Package uhid implements the Linux UHID transport for a virtual HID device.
// Wire layouts follow linux/uhid.h and https://docs.kernel.org/hid/uhid.html.
package uhid

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	Started uint32 = 2
	Stopped uint32 = 3
	Opened  uint32 = 4
	Closed  uint32 = 5
	Output  uint32 = 6

	maxData      = 4096
	eventSize    = 4380
	create2      = 11
	input2       = 12
	getReport    = 9
	setReport    = 13
	outputReport = 1
)

type Config struct {
	Name       string
	Bus        uint16
	VendorID   uint32
	ProductID  uint32
	Descriptor []byte
}

type Event struct {
	Type uint32
	Data []byte
}

type deviceFile interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
}

// Device owns its descriptor. Reads and writes may run concurrently with Close.
type Device struct {
	file      deviceFile
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool
}

// Open creates a device and waits for the kernel's UHID_START acknowledgement.
func Open(ctx context.Context, config Config) (*Device, error) {
	return open(ctx, config, func() (deviceFile, error) {
		return os.OpenFile("/dev/uhid", os.O_RDWR|unix.O_NONBLOCK, 0)
	})
}

func open(ctx context.Context, config Config, openFile func() (deviceFile, error)) (_ *Device, err error) {
	request, err := encodeCreate(config)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openFile()
	if err != nil {
		return nil, fmt.Errorf("open /dev/uhid: %w", err)
	}
	device := &Device{file: file}
	defer func() {
		if err != nil {
			err = errors.Join(err, device.Close())
		}
	}()
	if err = device.write(request); err != nil {
		return nil, fmt.Errorf("create UHID device: %w", err)
	}
	startup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	event, err := device.Read(startup)
	if err != nil {
		return nil, fmt.Errorf("wait for UHID_START: %w", err)
	}
	if event.Type != Started {
		return nil, fmt.Errorf("expected UHID_START, received event %d", event.Type)
	}
	return device, nil
}

func (config Config) Validate() error {
	if config.Name == "" || len(config.Name) >= 128 || strings.ContainsRune(config.Name, '\x00') {
		return errors.New("UHID name must contain 1-127 bytes without NUL")
	}
	if len(config.Descriptor) == 0 || len(config.Descriptor) > maxData {
		return fmt.Errorf("invalid HID descriptor length: %d", len(config.Descriptor))
	}
	return nil
}

func encodeCreate(config Config) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// UHID_CREATE2 is packed; the kernel zero-extends the omitted descriptor tail.
	buf := make([]byte, 280+len(config.Descriptor))
	binary.NativeEndian.PutUint32(buf, create2)
	copy(buf[4:132], config.Name)
	binary.NativeEndian.PutUint16(buf[260:262], uint16(len(config.Descriptor)))
	binary.NativeEndian.PutUint16(buf[262:264], config.Bus)
	binary.NativeEndian.PutUint32(buf[264:268], config.VendorID)
	binary.NativeEndian.PutUint32(buf[268:272], config.ProductID)
	copy(buf[280:], config.Descriptor)
	return buf, nil
}

// Read waits for an event without a background dispatcher. Unsupported control
// requests receive EIO replies so the kernel does not wait for a timeout.
func (d *Device) Read(ctx context.Context) (_ Event, err error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if d.closed.Load() {
		return Event{}, os.ErrClosed
	}
	deadline, _ := ctx.Deadline()
	if err := d.file.SetReadDeadline(deadline); err != nil {
		if d.closed.Load() {
			return Event{}, os.ErrClosed
		}
		return Event{}, fmt.Errorf("set UHID read deadline: %w", err)
	}
	cancelDone := make(chan struct{})
	var cancelErr error
	stop := context.AfterFunc(ctx, func() {
		cancelErr = d.file.SetReadDeadline(time.Now())
		close(cancelDone)
	})
	defer func() {
		if !stop() {
			<-cancelDone
			if cancelErr != nil && !d.closed.Load() {
				err = errors.Join(err, fmt.Errorf("interrupt UHID read: %w", cancelErr))
			}
		}
	}()

	for {
		buf := make([]byte, eventSize)
		n, readErr := d.file.Read(buf)
		if ctx.Err() != nil {
			return Event{}, ctx.Err()
		}
		if readErr != nil {
			if d.closed.Load() {
				return Event{}, os.ErrClosed
			}
			// File deadlines can expire just before the context's timer runs.
			if errors.Is(readErr, os.ErrDeadlineExceeded) && !deadline.IsZero() && !time.Now().Before(deadline) {
				return Event{}, context.DeadlineExceeded
			}
			return Event{}, fmt.Errorf("read UHID event: %w", readErr)
		}
		if n < 4 {
			return Event{}, fmt.Errorf("short UHID event: %d bytes", n)
		}
		// The ABI requires zero-extension of short kernel events.
		kind := binary.NativeEndian.Uint32(buf)
		switch kind {
		case Output:
			size := int(binary.NativeEndian.Uint16(buf[4100:4102]))
			if size > maxData || buf[4102] != outputReport {
				return Event{}, fmt.Errorf("invalid UHID output: size=%d report_type=%d", size, buf[4102])
			}
			return Event{Type: kind, Data: buf[4 : 4+size]}, nil
		case getReport, setReport:
			reply := make([]byte, 12)
			binary.NativeEndian.PutUint32(reply, kind+1)
			copy(reply[4:8], buf[4:8])
			binary.NativeEndian.PutUint16(reply[8:10], uint16(unix.EIO))
			if err := d.write(reply); err != nil {
				return Event{}, fmt.Errorf("reply to UHID control request: %w", err)
			}
		default:
			return Event{Type: kind}, nil
		}
	}
}

func (d *Device) WriteInput(data []byte) error {
	if len(data) > maxData {
		return fmt.Errorf("UHID input too large: %d bytes", len(data))
	}
	buf := make([]byte, 6+len(data))
	binary.NativeEndian.PutUint32(buf, input2)
	binary.NativeEndian.PutUint16(buf[4:6], uint16(len(data)))
	copy(buf[6:], data)
	return d.write(buf)
}

func (d *Device) write(buf []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() {
		return os.ErrClosed
	}
	n, err := d.file.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

// Close also unregisters the virtual device: the kernel destroys it when its
// UHID descriptor is closed. Closing interrupts an outstanding Read.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		if err := d.file.Close(); err != nil {
			d.closeErr = fmt.Errorf("close UHID device: %w", err)
		}
	})
	return d.closeErr
}
