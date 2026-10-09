package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pinterest/knox"
)

func TestParseACLFile(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		return path
	}

	testCases := []struct {
		name   string
		path   string
		acl    knox.ACL
		errMsg string
	}{
		{
			name: "valid acl file",
			path: writeFile("valid.json", `[{"type":"User","id":"testuser","access":"Admin"},{"type":"MachinePrefix","id":"auth","access":"Read"}]`),
			acl: knox.ACL{
				{Type: knox.User, ID: "testuser", AccessType: knox.Admin},
				{Type: knox.MachinePrefix, ID: "auth", AccessType: knox.Read},
			},
		},
		{
			name:   "missing file",
			path:   filepath.Join(dir, "does-not-exist.json"),
			errMsg: "could not read acl file",
		},
		{
			name:   "malformed json",
			path:   writeFile("malformed.json", `[{"type":"User",`),
			errMsg: "could not decode access list properly",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			acl, err := parseACLFile(tc.path)
			if tc.errMsg != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected %q in error, got: %v", tc.errMsg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
			if !reflect.DeepEqual(acl, tc.acl) {
				t.Errorf("expected acl %v, got %v", tc.acl, acl)
			}
		})
	}
}

// mockCreateServer creates a test server that records the acl form value sent
// on key creation requests.
func mockCreateServer(t *testing.T, gotACL *string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotACL = r.PostFormValue("acl")
		resp := &knox.Response{
			Status:    "ok",
			Code:      knox.OKCode,
			Host:      "test",
			Timestamp: 1234567890,
			Message:   "",
			Data:      uint64(1),
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

func TestRunCreateACL(t *testing.T) {
	dir := t.TempDir()
	aclFile := filepath.Join(dir, "acl.json")
	if err := os.WriteFile(aclFile, []byte(`[{"type":"User","id":"testuser","access":"Admin"}]`), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	testCases := []struct {
		name    string
		aclFlag string
		wantACL string
		errMsg  string
	}{
		{
			name:    "no acl flag sends empty acl",
			aclFlag: "",
			wantACL: "[]",
		},
		{
			name:    "acl flag sends parsed acl",
			aclFlag: aclFile,
			wantACL: `[{"type":"User","id":"testuser","access":"Admin"}]`,
		},
		{
			name:    "missing acl file",
			aclFlag: filepath.Join(dir, "does-not-exist.json"),
			errMsg:  "could not read acl file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotACL string
			srv := mockCreateServer(t, &gotACL)
			defer srv.Close()

			// Save original cli and flag values, restore after test
			origCli := cli
			origCreateACL := *createACL
			defer func() {
				cli = origCli
				*createACL = origCreateACL
			}()

			cli = knox.NewUncachedClient(
				srv.Listener.Addr().String(),
				srv.Client(),
				[]knox.AuthHandler{func() (string, string, knox.HTTP) { return "test", "0utest", nil }},
				"test-version",
			)

			*createACL = tc.aclFlag

			// Send key data to stdin
			oldStdin := os.Stdin
			stdinR, stdinW, _ := os.Pipe()
			os.Stdin = stdinR
			stdinW.Write([]byte("keydata"))
			stdinW.Close()
			defer func() { os.Stdin = oldStdin }()

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result := runCreate(nil, []string{"testkey"})

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			io.Copy(&buf, r)

			if tc.errMsg != "" {
				if result == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if !strings.Contains(result.Error(), tc.errMsg) {
					t.Errorf("expected %q in error, got: %v", tc.errMsg, result.error)
				}
				if result.serverError {
					t.Errorf("expected non-server error, got server error: %v", result.error)
				}
				return
			}
			if result != nil {
				t.Fatalf("expected nil error, got: %v", result.error)
			}
			if gotACL != tc.wantACL {
				t.Errorf("expected acl %s, got %s", tc.wantACL, gotACL)
			}
		})
	}
}
