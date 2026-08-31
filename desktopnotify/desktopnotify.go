// Package desktopnotify sends desktop notifications through the
// org.freedesktop.Notifications D-Bus interface.
package desktopnotify

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName           = "org.freedesktop.Notifications"
	objectPath        = dbus.ObjectPath("/org/freedesktop/Notifications")
	interfaceName     = "org.freedesktop.Notifications"
	applicationName   = "TPM-FIDO"
	expirationTimeout = int32(30_000)
)

var errClosed = errors.New("desktop notification client is closed")

type service interface {
	notify(ctx context.Context, replacesID uint32, title, body string) (uint32, error)
	closeNotification(ctx context.Context, id uint32) error
	close() error
}

// Client owns one replaceable desktop notification.
type Client struct {
	mu             sync.Mutex
	service        service
	notificationID uint32
	closed         bool
}

// New connects to the notification service on the session bus.
func New() (*Client, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect session bus: %w", err)
	}

	return newClient(&dbusService{
		conn:   conn,
		object: conn.Object(busName, objectPath),
	}), nil
}

func newClient(service service) *Client {
	return &Client{service: service}
}

// Show creates a notification or replaces the previous notification owned by
// this client.
func (c *Client) Show(ctx context.Context, title, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return errClosed
	}

	id, err := c.service.notify(ctx, c.notificationID, title, body)
	if err != nil {
		return err
	}

	c.notificationID = id
	return nil
}

// Close dismisses the current notification and closes the session bus
// connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	id := c.notificationID
	c.notificationID = 0
	c.mu.Unlock()

	var dismissErr error
	if id != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		dismissErr = c.service.closeNotification(ctx, id)
		cancel()
	}

	return errors.Join(dismissErr, c.service.close())
}

type dbusService struct {
	conn   *dbus.Conn
	object dbus.BusObject
}

func (s *dbusService) notify(ctx context.Context, replacesID uint32, title, body string) (uint32, error) {
	hints := map[string]dbus.Variant{
		"transient": dbus.MakeVariant(true),
		"urgency":   dbus.MakeVariant(byte(2)),
	}

	var id uint32
	err := s.object.CallWithContext(
		ctx,
		interfaceName+".Notify",
		0,
		applicationName,
		replacesID,
		"",
		title,
		body,
		[]string{},
		hints,
		expirationTimeout,
	).Store(&id)
	if err != nil {
		return 0, fmt.Errorf("show desktop notification: %w", err)
	}

	return id, nil
}

func (s *dbusService) closeNotification(ctx context.Context, id uint32) error {
	if call := s.object.CallWithContext(ctx, interfaceName+".CloseNotification", 0, id); call.Err != nil {
		return fmt.Errorf("close desktop notification: %w", call.Err)
	}
	return nil
}

func (s *dbusService) close() error {
	return s.conn.Close()
}
