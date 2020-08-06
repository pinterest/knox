package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
)

const TESTVAL int = 1

type mockAuthFail struct{}

func (a mockAuthFail) Authenticate(r *http.Request) (knox.Principal, error) {
	return nil, fmt.Errorf("Error!")
}
func (a mockAuthFail) IsUser(p knox.Principal) bool {
	return false
}

type mockAuthTrue struct{}

func (a mockAuthTrue) Authenticate(r *http.Request) (knox.Principal, error) {
	return nil, nil
}
func (a mockAuthTrue) IsUser(p knox.Principal) bool {
	return true
}

func mockFailureHandler(m KeyManager, principal knox.Principal, parameters map[string]string) (interface{}, *httpError) {
	return nil, errF(knox.InternalServerErrorCode, "")
}

func mockHandler(m KeyManager, principal knox.Principal, parameters map[string]string) (interface{}, *httpError) {
	return TESTVAL, nil
}

func mockRoute() route {
	return route{
		method:     "GET",
		path:       "/v0/keys/",
		handler:    mockHandler,
		id:         "test1",
		parameters: []parameter{},
	}
}

func mockFailureRoute() route {
	return route{
		method:     "GET",
		path:       "/v0/keys/",
		handler:    mockFailureHandler,
		id:         "test2",
		parameters: []parameter{},
	}
}

func TestAddDefaultAccess(t *testing.T) {
	dUID := "testuser2"
	u2 := auth.NewUser(dUID, []string{})
	a := &knox.Access{ID: dUID, AccessType: knox.Read, Type: knox.User}

	AddDefaultAccess(a)
	id := "testkeyid"
	uid := "testuser"
	acl := knox.ACL([]knox.Access{})
	data := []byte("testdata")
	u := auth.NewUser(uid, []string{})
	key := newKey(id, acl, data, u)
	if !u.CanAccess(key.ACL, knox.Admin) {
		t.Fatal("creator does not have access to his key")
	}
	if !u2.CanAccess(key.ACL, knox.Read) {
		t.Fatal("default access does not have access to his key")
	}
	if len(key.ACL) != 2 {
		text, _ := json.Marshal(key.ACL)
		t.Fatal("The Key's ACL is too big: " + string(text))
	}
	defaultAccess = []knox.Access{}

}

func TestParseFormParameter(t *testing.T) {
	p := postParameter("key")

	r, err := http.NewRequest("POST", "http://www.com/?key=nope", strings.NewReader("nokey=yup"))
	if err != nil {
		t.Fatal(err.Error())
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	s, ok := p.get(r)
	if ok {
		t.Fatal("Key parameter should not be present in post form")
	}

	r, err = http.NewRequest("POST", "http://www.com/?key=nope", strings.NewReader("key=yup"))
	if err != nil {
		t.Fatal(err.Error())
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	s, ok = p.get(r)
	if !ok {
		t.Fatal("Key parameter should be present in post form")
	}
	if s != "yup" {
		t.Fatal("Key should be yup")
	}

	// This should cause some problems
	r, err = http.NewRequest("POST", "http://www.com/?key=nope", nil)
	if err != nil {
		t.Fatal(err.Error())
	}
	s, ok = p.get(r)
	if ok {
		t.Fatal("Key parameter should not be present in nil request body")
	}

}

func checkinternalServerErrorResponse(t *testing.T, w *httptest.ResponseRecorder) {
	if w.Code != HTTPErrMap[knox.InternalServerErrorCode].Code {
		t.Fatal("unexpected response code")
	}
	var resp knox.Response
	err := json.Unmarshal([]byte(w.Body.String()), &resp)
	if err != nil {
		t.Fatal("Test returned invalid JSON data")
	}
	if resp.Data != nil {
		t.Fatal("Test returned invalid data")
	}
	if resp.Status != "error" {
		t.Fatal("unexpected status")
	}
	if resp.Code != knox.InternalServerErrorCode {
		t.Fatal("unexpected error code")
	}
	if resp.Message != "" {
		t.Fatal("Wrong message")
	}
	if resp.Host == "" {
		t.Fatal("no hostname present")
	}
	if resp.Timestamp > time.Now().UnixNano() {
		t.Fatal("time is in the future")
	}
}

func TestErrorHandler(t *testing.T) {
	testErr := errF(knox.InternalServerErrorCode, "")
	handler := writeErr(testErr)

	w := httptest.NewRecorder()
	handler(w, nil)
	checkinternalServerErrorResponse(t, w)
}

func TestNewKeyVersion(t *testing.T) {
	data := []byte("testdata")
	status := knox.Active
	beforeTime := time.Now().UnixNano()
	version := newKeyVersion(data, status)
	afterTime := time.Now().UnixNano()
	if !bytes.Equal(version.Data, data) {
		t.Fatal("version data mismatch")
	}
	if version.CreationTime < beforeTime || version.CreationTime > afterTime {
		t.Fatal("Creation time does not fit in time bounds")
	}
	if version.Status != status {
		t.Fatal("version status doesn't match")
	}
	version2 := newKeyVersion(data, status)
	if version.ID == version2.ID {
		t.Fatal("version ids are deterministic")
	}
}

func TestNewKey(t *testing.T) {
	id := "testkeyid"
	uid := "testuser"
	acl := knox.ACL([]knox.Access{{ID: "testmachine", AccessType: knox.Admin, Type: knox.Machine}})
	data := []byte("testdata")
	u := auth.NewUser(uid, []string{})
	key := newKey(id, acl, data, u)
	if key.ID != id {
		t.Fatal("ID does not match: " + key.ID + "!=" + id)
	}
	if len(key.VersionList) != 1 || !bytes.Equal(key.VersionList[0].Data, data) {
		t.Fatal("data does not match: " + string(key.VersionList[0].Data) + "!=" + string(data))
	}
	if !u.CanAccess(key.ACL, knox.Admin) {
		t.Fatal("creator does not have access to his key")
	}
	if len(key.ACL) != len(defaultAccess)+2 {
		text, _ := json.Marshal(key.ACL)
		t.Fatal("The Key's ACL is too big: " + string(text))
	}

}

func TestBuildRequest(t *testing.T) {
	u := auth.NewUser("Man", []string{})
	m := auth.NewMachine("Robot")
	params := map[string]string{"data": "secret", "keyID": "not_secret"}
	req := &http.Request{
		URL:        &url.URL{Path: "path"},
		TLS:        &tls.ConnectionState{CipherSuite: 1},
		Method:     "GET",
		RemoteAddr: "10.1.1.1",
	}

	r := buildRequest(req, m, params)
	if r.Method != "GET" {
		t.Errorf("Method Should be GET not %q", r.Method)
	}
	if r.RemoteAddr != "10.1.1.1" {
		t.Errorf("Method Should be 10.1.1.1 not %q", r.RemoteAddr)
	}
	if r.Path != "path" {
		t.Errorf("Path Should be path not %q", r.Path)
	}
	if r.Principal != "Robot" {
		t.Errorf("Principal Should be Robot not %q", r.Principal)
	}
	if r.AuthType != "machine" {
		t.Errorf("AuthType Should be machine not %q", r.AuthType)
	}
	if r.TLSCipher != 1 {
		t.Errorf("TLSCipher Should be 1 not %d", r.TLSCipher)
	}
	if v, ok := r.Parameters["data"]; !ok || v == "secret_sauce" {
		t.Fatal("data should be scrubbed, but still present.")
	}
	r = buildRequest(req, u, params)
	if r.AuthType != "user" {
		t.Errorf("AuthType Should be user not %q", r.AuthType)
	}
	r = buildRequest(req, nil, params)
	if r.AuthType != "" {
		t.Errorf("AuthType Should be \"\" not %q", r.AuthType)
	}
	if r.Principal != "" {
		t.Errorf("Principal Should be \"\" not %q", r.Principal)
	}
}

func TestScrub(t *testing.T) {
	r := scrub(map[string]string{"keyID": "not_secret", "data": "secret_sauce"})
	if v, ok := r["keyID"]; !ok || v != "not_secret" {
		t.Fatal("KeyID not expected to be scrubbed.")
	}
	if v, ok := r["data"]; !ok || v == "secret_sauce" {
		t.Fatal("data should be scrubbed, but still present.")
	}
}
