package test

import (
	"errors"
	"testing"
)

// T is a helper struct for tests that wraps *testing.T.
type T struct {
	*testing.T
}

// FromT creates a new test helper from a *testing.T.
func FromT(t *testing.T) *T {
	t.Helper()
	return &T{t}
}

// Assert fails the test if the condition is false.
func (t *T) Assert(condition bool, msgAndArgs ...any) {
	t.Helper()
	if !condition {
		if len(msgAndArgs) > 0 {
			if format, ok := msgAndArgs[0].(string); ok {
				t.Fatalf(format, msgAndArgs[1:]...)
			} else {
				t.Fatal(msgAndArgs...)
			}
		} else {
			t.Fatal("assertion failed")
		}
	}
}

// Assertf fails the test if the condition is false, with a formatted message.
func (t *T) Assertf(condition bool, format string, args ...any) {
	t.Helper()
	if !condition {
		t.Fatalf(format, args...)
	}
}

// CheckErr fails the test if err is not nil.
func (t *T) CheckErr(err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ExpectErr fails the test if err is not the expected error.
// It uses errors.Is to check for wrapped errors.
func (t *T) ExpectErr(err, expectedErr error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error '%v', but got nil", expectedErr)
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error '%v', but got '%v'", expectedErr, err)
	}
}

// ShouldPanic fails the test if the provided function f does not panic.
func (t *T) ShouldPanic(f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic, but did not get one")
		}
	}()
	f()
}
