package main

import (
	"errors"
	"fmt"
)

// APIError represents an error response from the BOB API with HTTP status code.
type APIError struct {
	StatusCode int
	Body       string
	Message    string // parsed from JSON {"error": "..."} if possible
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error (%d): %s", e.StatusCode, e.Body)
}

// IsAPIStatus checks if the error is an APIError with the given HTTP status code.
func IsAPIStatus(err error, code int) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == code
	}
	return false
}

// APIErrorMessage extracts the error message from an APIError, or falls back to err.Error().
func APIErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Message != "" {
		return apiErr.Message
	}
	return err.Error()
}

// TODO: Update apiPost, apiGet, apiPut, apiDelete, and apiPostNoAuth in main.go
// to return *APIError instead of plain errors when the HTTP response has a
// non-2xx status code. This will allow callers to use IsAPIStatus() instead of
// fragile string matching (e.g. strings.Contains(err.Error(), "409")).
