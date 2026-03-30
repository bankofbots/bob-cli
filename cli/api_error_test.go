package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 409, Body: `{"error":"agent already exists"}`}
	want := `api error (409): {"error":"agent already exists"}`
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestIsAPIStatus_Match(t *testing.T) {
	err := &APIError{StatusCode: 403, Body: "forbidden"}
	if !IsAPIStatus(err, 403) {
		t.Error("IsAPIStatus should return true for matching status code")
	}
}

func TestIsAPIStatus_NoMatch(t *testing.T) {
	err := &APIError{StatusCode: 403, Body: "forbidden"}
	if IsAPIStatus(err, 409) {
		t.Error("IsAPIStatus should return false for non-matching status code")
	}
}

func TestIsAPIStatus_WrappedError(t *testing.T) {
	inner := &APIError{StatusCode: 409, Body: "conflict"}
	wrapped := fmt.Errorf("registration failed: %w", inner)
	if !IsAPIStatus(wrapped, 409) {
		t.Error("IsAPIStatus should unwrap and match wrapped APIError")
	}
}

func TestIsAPIStatus_NonAPIError(t *testing.T) {
	err := errors.New("network timeout")
	if IsAPIStatus(err, 500) {
		t.Error("IsAPIStatus should return false for non-APIError")
	}
}

func TestIsAPIStatus_Nil(t *testing.T) {
	if IsAPIStatus(nil, 500) {
		t.Error("IsAPIStatus should return false for nil error")
	}
}

func TestAPIErrorMessage_WithMessage(t *testing.T) {
	err := &APIError{StatusCode: 400, Body: `{"error":"bad request"}`, Message: "bad request"}
	if got := APIErrorMessage(err); got != "bad request" {
		t.Errorf("APIErrorMessage = %q, want %q", got, "bad request")
	}
}

func TestAPIErrorMessage_WithoutMessage(t *testing.T) {
	err := &APIError{StatusCode: 500, Body: "internal server error"}
	want := `api error (500): internal server error`
	if got := APIErrorMessage(err); got != want {
		t.Errorf("APIErrorMessage = %q, want %q", got, want)
	}
}

func TestAPIErrorMessage_RegularError(t *testing.T) {
	err := errors.New("something broke")
	if got := APIErrorMessage(err); got != "something broke" {
		t.Errorf("APIErrorMessage = %q, want %q", got, "something broke")
	}
}
