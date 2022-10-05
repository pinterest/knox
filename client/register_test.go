package client

import (
	"testing"
	"time"
)

func TestParseTimeout(t *testing.T) {
	testCases := []struct {
		str string
		dur time.Duration
	}{
		{"5", 5 * time.Second},
		{"5s", 5 * time.Second},
		{"0.5s", 500 * time.Millisecond},
		{"500ms", 500 * time.Millisecond},
	}

	for _, tc := range testCases {
		r, err := parseTimeout(tc.str)
		if err != nil {
			t.Errorf("error parsing value %s: %s", tc.str, err)
			continue
		}
		if r != tc.dur {
			t.Errorf("mismatch: %s should parse to %s", tc.str, tc.dur.String())
		}
	}
}
