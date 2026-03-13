package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinterest/knox"
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

// mockServer creates a test server that returns the given key
func mockServer(t *testing.T, key knox.Key) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &knox.Response{
			Status:    "ok",
			Code:      knox.OKCode,
			Host:      "test",
			Timestamp: 1234567890,
			Message:   "",
			Data:      key,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal response: %v", err)
		}
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

// mockErrorServer creates a test server that returns errors
func mockErrorServer(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &knox.Response{
			Status:    "error",
			Code:      knox.InternalServerErrorCode,
			Host:      "test",
			Timestamp: 1234567890,
			Message:   "server error",
			Data:      nil,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal response: %v", err)
		}
		w.WriteHeader(500)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

func TestFetchAndPrintKey_Success(t *testing.T) {
	expected := knox.Key{
		ID:          "testkey",
		ACL:         knox.ACL([]knox.Access{}),
		VersionList: knox.KeyVersionList{},
		VersionHash: "VersionHash",
	}

	srv := mockServer(t, expected)
	defer srv.Close()

	// Save original cli and restore after test
	origCli := cli
	defer func() { cli = origCli }()

	// Create an uncached client for testing
	cli = knox.NewUncachedClient(
		srv.Listener.Addr().String(),
		srv.Client(),
		[]knox.AuthHandler{func() (string, string, knox.HTTP) { return "test", "0utest", nil }},
		"test-version",
	)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := fetchAndPrintKey("testkey", "5s")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if result != nil {
		t.Fatalf("expected nil error, got: %v", result.error)
	}

	// Verify output is valid JSON containing expected key
	var outputKey knox.Key
	if err := json.Unmarshal(buf.Bytes(), &outputKey); err != nil {
		t.Fatalf("output is not valid JSON: %v, output: %s", err, buf.String())
	}

	if outputKey.ID != expected.ID {
		t.Errorf("expected key ID %s, got %s", expected.ID, outputKey.ID)
	}
	if outputKey.VersionHash != expected.VersionHash {
		t.Errorf("expected VersionHash %s, got %s", expected.VersionHash, outputKey.VersionHash)
	}
}

func TestFetchAndPrintKey_InvalidTimeout(t *testing.T) {
	result := fetchAndPrintKey("testkey", "invalid")

	if result == nil {
		t.Fatal("expected error for invalid timeout, got nil")
	}
	if !strings.Contains(result.Error(), "invalid value for timeout flag") {
		t.Errorf("expected 'invalid value for timeout flag' in error, got: %v", result.error)
	}
}

func TestFetchAndPrintKey_Timeout(t *testing.T) {
	srv := mockErrorServer(t)
	defer srv.Close()

	// Save original cli and restore after test
	origCli := cli
	defer func() { cli = origCli }()

	// Create an uncached client for testing
	cli = knox.NewUncachedClient(
		srv.Listener.Addr().String(),
		srv.Client(),
		[]knox.AuthHandler{func() (string, string, knox.HTTP) { return "test", "0utest", nil }},
		"test-version",
	)

	// Use a very short timeout to trigger timeout quickly
	result := fetchAndPrintKey("testkey", "50ms")

	if result == nil {
		t.Fatal("expected error for timeout, got nil")
	}
	if !strings.Contains(result.Error(), "timeout") {
		t.Errorf("expected 'timeout' in error, got: %v", result.error)
	}
}

func TestRunRegister_GFlagRequiresK(t *testing.T) {
	// Save original flag values and restore after test
	origRegisterAndGet := *registerAndGet
	origRegisterKey := *registerKey
	origRegisterKeyFile := *registerKeyFile
	defer func() {
		*registerAndGet = origRegisterAndGet
		*registerKey = origRegisterKey
		*registerKeyFile = origRegisterKeyFile
	}()

	// Test: -g without -k should fail
	*registerAndGet = true
	*registerKey = ""
	*registerKeyFile = ""

	result := runRegister(nil, nil)

	if result == nil {
		t.Fatal("expected error when -g is used without -k, got nil")
	}
	if !strings.Contains(result.Error(), "-g flag requires -k") {
		t.Errorf("expected '-g flag requires -k' in error, got: %v", result.error)
	}
}

func TestRunRegister_GFlagWithFFile(t *testing.T) {
	// Save original flag values and restore after test
	origRegisterAndGet := *registerAndGet
	origRegisterKey := *registerKey
	origRegisterKeyFile := *registerKeyFile
	defer func() {
		*registerAndGet = origRegisterAndGet
		*registerKey = origRegisterKey
		*registerKeyFile = origRegisterKeyFile
	}()

	// Test: -g with -f (but without -k) should fail early
	*registerAndGet = true
	*registerKey = ""
	*registerKeyFile = "somefile.txt"

	result := runRegister(nil, nil)

	if result == nil {
		t.Fatal("expected error when -g is used with -f but without -k, got nil")
	}
	if !strings.Contains(result.Error(), "-g flag requires -k") {
		t.Errorf("expected '-g flag requires -k' in error, got: %v", result.error)
	}
}

func TestRunRegister_UncachedModeRequiresG(t *testing.T) {
	// Save original cli and flag values, restore after test
	origCli := cli
	origRegisterAndGet := *registerAndGet
	origRegisterKey := *registerKey
	origRegisterKeyFile := *registerKeyFile
	defer func() {
		cli = origCli
		*registerAndGet = origRegisterAndGet
		*registerKey = origRegisterKey
		*registerKeyFile = origRegisterKeyFile
	}()

	// Set up an uncached client
	cli = &knox.UncachedHTTPClient{}

	// Test: uncached mode without -g should fail
	*registerAndGet = false
	*registerKey = "testkey"
	*registerKeyFile = ""

	result := runRegister(nil, nil)

	if result == nil {
		t.Fatal("expected error in uncached mode without -g, got nil")
	}
	if !strings.Contains(result.Error(), "cannot register keys in no-cache mode") {
		t.Errorf("expected 'cannot register keys in no-cache mode' in error, got: %v", result.error)
	}
}

func TestRunRegister_UncachedModeWithGAndK(t *testing.T) {
	expected := knox.Key{
		ID:          "testkey",
		ACL:         knox.ACL([]knox.Access{}),
		VersionList: knox.KeyVersionList{},
		VersionHash: "VersionHash",
	}

	srv := mockServer(t, expected)
	defer srv.Close()

	// Save original cli and flag values, restore after test
	origCli := cli
	origRegisterAndGet := *registerAndGet
	origRegisterKey := *registerKey
	origRegisterKeyFile := *registerKeyFile
	origRegisterTimeout := *registerTimeout
	defer func() {
		cli = origCli
		*registerAndGet = origRegisterAndGet
		*registerKey = origRegisterKey
		*registerKeyFile = origRegisterKeyFile
		*registerTimeout = origRegisterTimeout
	}()

	// Set up an uncached client
	cli = knox.NewUncachedClient(
		srv.Listener.Addr().String(),
		srv.Client(),
		[]knox.AuthHandler{func() (string, string, knox.HTTP) { return "test", "0utest", nil }},
		"test-version",
	)

	// Test: uncached mode with -g and -k should succeed
	*registerAndGet = true
	*registerKey = "testkey"
	*registerKeyFile = ""
	*registerTimeout = "5s"

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := runRegister(nil, nil)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if result != nil {
		t.Fatalf("expected nil error, got: %v", result.error)
	}

	// Verify output contains the key
	var outputKey knox.Key
	if err := json.Unmarshal(buf.Bytes(), &outputKey); err != nil {
		t.Fatalf("output is not valid JSON: %v, output: %s", err, buf.String())
	}

	if outputKey.ID != expected.ID {
		t.Errorf("expected key ID %s, got %s", expected.ID, outputKey.ID)
	}
}
