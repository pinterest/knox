package knox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestMockClient(t *testing.T) {
	p := "primary"
	a := []string{"active1", "active2"}
	k0 := Key{
		VersionList: []KeyVersion{
			{Data: []byte(p), Status: Primary}, {Data: []byte(a[0]), Status: Active}, {Data: []byte(a[1]), Status: Active}}}

	m := NewMock(p, a)
	p1 := m.GetPrimary()
	if p1 != p {
		t.Fatalf("Expected %s : Got %s for primary key", p, p1)
	}
	r := m.GetActive()
	if len(r) != len(a) {
		t.Fatalf("For active keys: length %d should equal length %d", len(r), len(a))
	}
	for i := range a {
		if r[i] != a[i] {
			t.Fatalf("%s should equal %s", r[i], a[i])
		}
	}
	k1 := m.GetKeyObject()
	if !reflect.DeepEqual(k0, k1) {
		t.Fatalf("Got %v, Want %v", k1, k0)
	}

}

func buildGoodResponse(data interface{}) ([]byte, error) {
	resp := &Response{
		Status:    "ok",
		Code:      OKCode,
		Host:      "test",
		Timestamp: 1234567890,
		Message:   "",
		Data:      data,
	}
	return json.Marshal(resp)

}

func buildInternalServerErrorResponse(data interface{}) ([]byte, error) {
	resp := &Response{
		Status:    "err",
		Code:      InternalServerErrorCode,
		Host:      "test",
		Timestamp: 1234567890,
		Message:   "Internal Server Error",
		Data:      data,
	}
	return json.Marshal(resp)

}

// buildServer returns a server. Call Close when finished.
func buildServer(code int, body []byte, a func(r *http.Request)) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a(r)
		w.WriteHeader(code)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

func buildConcurrentServer(code int, t *testing.T, a func(r *http.Request) []byte) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := a(r)
		w.WriteHeader(code)
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}))
}

func TestGetKey(t *testing.T) {
	expected := Key{
		ID:          "testkey",
		ACL:         ACL([]Access{}),
		VersionList: KeyVersionList{},
		VersionHash: "VersionHash",
	}
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("%s is not GET", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/")
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	k, err := cli.GetKey("testkey")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if k.ID != expected.ID {
		t.Fatalf("%s does not equal %s", k.ID, expected.ID)
	}
	if len(k.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(k.ACL), len(expected.ACL))
	}
	if len(k.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(k.VersionList), len(expected.VersionList))
	}
	if k.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", k.VersionHash, expected.VersionHash)
	}
	if k.Path != "" {
		t.Fatalf("path '%v' is not empty", k.Path)
	}
}

func TestGetKeys(t *testing.T) {
	expected := []string{"a", "b", "c"}
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("%s is not GET", r.Method)
		}
		if r.URL.Path != "/v0/keys/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/")
		}
		if r.URL.RawQuery != "y=x" {
			t.Fatalf("%s is not %s", r.URL.RawQuery, "y=x")
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	k, err := cli.GetKeys(map[string]string{"y": "x"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(k) != 3 {
		t.Fatalf("%d is not 3", len(k))
	}
	if k[0] != "a" {
		t.Fatalf("%s is not %s", k[0], "a")
	}
	if k[1] != "b" {
		t.Fatalf("%s is not %s", k[0], "b")
	}
	if k[2] != "c" {
		t.Fatalf("%s is not %s", k[0], "c")
	}
}

func TestCreateKey(t *testing.T) {
	expected := uint64(123)
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("%s is not POST", r.Method)
		}
		if r.URL.Path != "/v0/keys/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/")
		}
		r.ParseForm()
		if r.PostForm["data"][0] != "ZGF0YQ==" {
			t.Fatalf("%s is not expected: %s", r.PostForm["data"][0], "ZGF0YQ==")
		}
		if r.PostForm["id"][0] != "testkey" {
			t.Fatalf("%s is not expected: %s", r.PostForm["id"][0], "testkey")
		}
		if r.PostForm["acl"][0] == "" {
			t.Fatalf("%s is empty", r.PostForm["acl"][0])
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	acl := ACL([]Access{
		{
			Type:       User,
			AccessType: Read,
			ID:         "test",
		},
	})

	badACL := ACL([]Access{
		{
			Type:       233,
			AccessType: 80927,
			ID:         "test",
		},
	})
	_, err = cli.CreateKey("testkey", []byte("data"), badACL)
	if err == nil {
		t.Fatal("error is nil")
	}

	k, err := cli.CreateKey("testkey", []byte("data"), acl)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if k != expected {
		t.Fatalf("%d is not %d", k, expected)
	}
}

func TestAddVersion(t *testing.T) {
	expected := uint64(123)
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("%s is not POST", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/versions/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/versions/")
		}
		r.ParseForm()
		if r.PostForm["data"][0] != "ZGF0YQ==" {
			t.Fatalf("%s is not expected: %s", r.PostForm["data"][0], "ZGF0YQ==")
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	k, err := cli.AddVersion("testkey", []byte("data"))
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if k != expected {
		t.Fatalf("%d is not %d", k, expected)
	}
}

func TestDeleteKey(t *testing.T) {
	expected := ""
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "DELETE" {
			t.Fatalf("%s is not DELETE", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/")
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	err = cli.DeleteKey("testkey")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
}

func TestPutVersion(t *testing.T) {
	resp, err := buildGoodResponse("")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "PUT" {
			t.Fatalf("%s is not PUT", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/versions/123/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/versions/123/")
		}
		r.ParseForm()
		if r.PostForm["status"][0] != "\"Primary\"" {
			t.Fatalf("%s is not expected: %s", r.PostForm["status"][0], "\"Primary\"")
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	err = cli.UpdateVersion("testkey", "123", 2342)
	if err == nil {
		t.Fatal("error is nil")
	}

	err = cli.UpdateVersion("testkey", "123", Primary)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
}

func TestPutAccess(t *testing.T) {
	resp, err := buildGoodResponse("")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "PUT" {
			t.Fatalf("%s is not PUT", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/access/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/access/")
		}
		r.ParseForm()
		if r.PostForm["acl"][0] == "" {
			t.Fatalf("%s is empty", r.PostForm["access"][0])
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	a := Access{
		Type:       User,
		AccessType: Read,
		ID:         "test",
	}

	badA := Access{
		Type:       233,
		AccessType: 80927,
		ID:         "test",
	}

	err = cli.PutAccess("testkey", badA)
	if err == nil {
		t.Fatal("error is nil")
	}

	err = cli.PutAccess("testkey", a)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
}

func TestConcurrentDeletes(t *testing.T) {
	var ops uint64
	srv := buildConcurrentServer(200, t, func(r *http.Request) []byte {
		if r.Method != "DELETE" {
			t.Fatalf("%s is not DELETE", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey1/" &&
			r.URL.Path != "/v0/keys/testkey2/" {
			t.Fatalf("%s is not the path for testkey1 or testkey2", r.URL.Path)
		}
		atomic.AddUint64(&ops, 1)
		var resp []byte
		var err error
		if ops%2 == 0 {
			resp, err = buildGoodResponse("")
			if err != nil {
				t.Fatalf("%s is not nil", err)
			}
		} else {
			resp, err = buildInternalServerErrorResponse("")
			if err != nil {
				t.Fatalf("%s is not nil", err)
			}
		}
		return resp
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	// Delete 2 independent keys in succession.
	err := cli.DeleteKey("testkey1")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = cli.DeleteKey("testkey2")
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	// Verify that our atomic counter was incremented 4 times (2 attempts each)
	if ops != 4 {
		t.Fatalf("%d total client attempts is not 4", ops)
	}
}

func TestGetKeyWithStatus(t *testing.T) {
	expected := Key{
		ID:          "testkey",
		ACL:         ACL([]Access{}),
		VersionList: KeyVersionList{},
		VersionHash: "VersionHash",
	}
	resp, err := buildGoodResponse(expected)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	srv := buildServer(200, resp, func(r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("%s is not GET", r.Method)
		}
		if r.URL.Path != "/v0/keys/testkey/" {
			t.Fatalf("%s is not %s", r.URL.Path, "/v0/keys/testkey/")
		}

		statusParams, ok := r.URL.Query()["status"]
		if !ok {
			t.Fatal("query param for status is missing")
		}

		var status VersionStatus
		err := json.Unmarshal([]byte(statusParams[0]), &status)
		if err != nil || status != Inactive {
			t.Fatal("query param for status is incorrect:", err)
		}
	})
	defer srv.Close()

	cli := MockClient(srv.Listener.Addr().String())

	k, err := cli.GetKeyWithStatus("testkey", Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if k.ID != expected.ID {
		t.Fatalf("%s does not equal %s", k.ID, expected.ID)
	}
	if len(k.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(k.ACL), len(expected.ACL))
	}
	if len(k.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(k.VersionList), len(expected.VersionList))
	}
	if k.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", k.VersionHash, expected.VersionHash)
	}
	if k.Path != "" {
		t.Fatalf("path '%v' is not empty", k.Path)
	}
}
