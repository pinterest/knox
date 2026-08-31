package knox

import "fmt"

// APIError is an error response returned by the Knox API.
type APIError struct {
	StatusCode int
	Code       int
	message    string
	cause      error
}

func (e *APIError) Unwrap() error {
	return e.cause
}

func (e *APIError) Error() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("knox API error: HTTP status %d, code %d", e.StatusCode, e.Code)
}
