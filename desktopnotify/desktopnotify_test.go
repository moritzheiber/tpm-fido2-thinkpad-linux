package desktopnotify

import (
	"context"
	"errors"
	"testing"
)

type notificationCall struct {
	replacesID uint32
	title      string
	body       string
}

type fakeService struct {
	calls           []notificationCall
	notifyIDs       []uint32
	notifyErrors    []error
	closedIDs       []uint32
	closeNotifyErr  error
	connectionClose bool
	connectionErr   error
}

func (f *fakeService) notify(_ context.Context, replacesID uint32, title, body string) (uint32, error) {
	f.calls = append(f.calls, notificationCall{replacesID: replacesID, title: title, body: body})
	i := len(f.calls) - 1
	if i < len(f.notifyErrors) && f.notifyErrors[i] != nil {
		return 0, f.notifyErrors[i]
	}
	if i < len(f.notifyIDs) {
		return f.notifyIDs[i], nil
	}
	return uint32(i + 1), nil
}

func (f *fakeService) closeNotification(_ context.Context, id uint32) error {
	f.closedIDs = append(f.closedIDs, id)
	return f.closeNotifyErr
}

func (f *fakeService) close() error {
	f.connectionClose = true
	return f.connectionErr
}

func TestShowFirstNotificationDoesNotReplace(t *testing.T) {
	service := &fakeService{notifyIDs: []uint32{41}}
	client := newClient(service)

	if err := client.Show(context.Background(), "TPM-FIDO", "Touch the sensor"); err != nil {
		t.Fatalf("Show: %v", err)
	}
	if len(service.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(service.calls))
	}
	if service.calls[0].replacesID != 0 {
		t.Errorf("replacesID = %d, want 0", service.calls[0].replacesID)
	}
}

func TestShowReplacesPreviousNotification(t *testing.T) {
	service := &fakeService{notifyIDs: []uint32{41, 42}}
	client := newClient(service)

	if err := client.Show(context.Background(), "TPM-FIDO", "Touch the sensor"); err != nil {
		t.Fatal(err)
	}
	if err := client.Show(context.Background(), "TPM-FIDO", "Try again"); err != nil {
		t.Fatal(err)
	}
	if service.calls[1].replacesID != 41 {
		t.Errorf("second replacesID = %d, want 41", service.calls[1].replacesID)
	}
}

func TestShowKeepsPreviousIDWhenUpdateFails(t *testing.T) {
	sentinel := errors.New("notify failed")
	service := &fakeService{
		notifyIDs:    []uint32{41, 0, 43},
		notifyErrors: []error{nil, sentinel, nil},
	}
	client := newClient(service)

	if err := client.Show(context.Background(), "TPM-FIDO", "Touch the sensor"); err != nil {
		t.Fatal(err)
	}
	if err := client.Show(context.Background(), "TPM-FIDO", "Try again"); !errors.Is(err, sentinel) {
		t.Fatalf("update error = %v, want %v", err, sentinel)
	}
	if err := client.Show(context.Background(), "TPM-FIDO", "Try once more"); err != nil {
		t.Fatal(err)
	}
	if service.calls[2].replacesID != 41 {
		t.Errorf("third replacesID = %d, want previous successful ID 41", service.calls[2].replacesID)
	}
}

func TestCloseDismissesCurrentNotificationAndClosesConnection(t *testing.T) {
	service := &fakeService{notifyIDs: []uint32{41}}
	client := newClient(service)
	if err := client.Show(context.Background(), "TPM-FIDO", "Touch the sensor"); err != nil {
		t.Fatal(err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(service.closedIDs) != 1 || service.closedIDs[0] != 41 {
		t.Errorf("closedIDs = %v, want [41]", service.closedIDs)
	}
	if !service.connectionClose {
		t.Error("connection was not closed")
	}
}

func TestCloseWithoutNotificationOnlyClosesConnection(t *testing.T) {
	service := &fakeService{}
	client := newClient(service)

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if len(service.closedIDs) != 0 {
		t.Errorf("closedIDs = %v, want none", service.closedIDs)
	}
	if !service.connectionClose {
		t.Error("connection was not closed")
	}
}

func TestCloseReturnsDismissAndConnectionErrors(t *testing.T) {
	dismissErr := errors.New("dismiss failed")
	connectionErr := errors.New("connection close failed")
	service := &fakeService{
		notifyIDs:      []uint32{41},
		closeNotifyErr: dismissErr,
		connectionErr:  connectionErr,
	}
	client := newClient(service)
	if err := client.Show(context.Background(), "TPM-FIDO", "Touch the sensor"); err != nil {
		t.Fatal(err)
	}

	err := client.Close()
	if !errors.Is(err, dismissErr) {
		t.Errorf("Close error = %v, want dismiss error", err)
	}
	if !errors.Is(err, connectionErr) {
		t.Errorf("Close error = %v, want connection error", err)
	}
}
