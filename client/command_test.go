package client

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/pinterest/knox"
)

func TestMetricsKeyForErrorStatus(t *testing.T) {
	ignoredAPIErrors := []struct {
		statusCode int
		code       int
	}{
		{http.StatusBadRequest, knox.NoKeyIDCode},
		{http.StatusBadRequest, knox.KeyIdentifierExistsCode},
		{http.StatusBadRequest, knox.NoKeyDataCode},
		{http.StatusBadRequest, knox.BadRequestDataCode},
		{http.StatusBadRequest, knox.BadKeyFormatCode},
		{http.StatusBadRequest, knox.BadPrincipalIdentifier},
		{http.StatusUnauthorized, knox.UnauthenticatedCode},
		{http.StatusForbidden, knox.UnauthorizedCode},
		{http.StatusNotFound, knox.KeyVersionDoesNotExistCode},
		{http.StatusNotFound, knox.KeyIdentifierDoesNotExistCode},
		{http.StatusNotFound, knox.NotFoundCode},
	}

	if got := metricsKeyForErrorStatus(nil); got != "success" {
		t.Fatalf("Expected success, got %q", got)
	}
	if got := metricsKeyForErrorStatus(&ErrorStatus{error: errors.New("invalid argument")}); got != "ignored_failure" {
		t.Fatalf("Expected ignored_failure for local error, got %q", got)
	}

	for _, test := range ignoredAPIErrors {
		err := fmt.Errorf("command failed: %w", &knox.APIError{StatusCode: test.statusCode, Code: test.code})
		if got := metricsKeyForErrorStatus(&ErrorStatus{error: err, serverError: true}); got != "ignored_failure" {
			t.Errorf("Expected ignored_failure for status/code %d/%d, got %q", test.statusCode, test.code, got)
		}
	}
}

func TestMetricsKeyKeepsUnexpectedErrorsAsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"server error", &knox.APIError{StatusCode: http.StatusInternalServerError, Code: knox.InternalServerErrorCode}},
		{"unknown code", &knox.APIError{StatusCode: http.StatusBadRequest, Code: 1000}},
		{"mismatched status", &knox.APIError{StatusCode: http.StatusNotFound, Code: knox.BadRequestDataCode}},
		{"zero-value API error", &knox.APIError{}},
		{"transport error", errors.New("transport failed")},
		{"malformed response", errors.New("malformed response")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := metricsKeyForErrorStatus(&ErrorStatus{error: test.err, serverError: true}); got != "failure" {
				t.Fatalf("Expected failure, got %q", got)
			}
		})
	}
}
