package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestDeviceRunErrorPreservesFailures(t *testing.T) {
	failure := errors.New("close failed")
	for _, err := range []error{nil, context.Canceled, fmt.Errorf("read: %w", context.Canceled)} {
		if got := deviceRunError(err); got != nil {
			t.Errorf("expected shutdown was reported as a failure: %v", got)
		}
	}
	for _, err := range []error{
		failure,
		errors.Join(context.Canceled, failure),
		fmt.Errorf("shutdown: %w", errors.Join(context.Canceled, failure)),
	} {
		if got := deviceRunError(err); !errors.Is(got, failure) {
			t.Errorf("lost cleanup failure: %v", got)
		}
	}
}
