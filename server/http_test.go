// This is for testing routes in api from a black box perspective
package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"

	. "github.com/pinterest/knox/server"
)

var router *mux.Router

func getHTTPData(method string, path string, body url.Values, data interface{}) (string, error) {
	r, reqErr := http.NewRequest(method, path, bytes.NewBufferString(body.Encode()))
	r.Header.Set("Authorization", "0u"+"testuser")
	if reqErr != nil {
		return "", reqErr
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	getRouter().ServeHTTP(w, r)
	resp := &knox.Response{}
	resp.Data = data
	decoder := json.NewDecoder(w.Body)
	err := decoder.Decode(resp)
	if err != nil {
		return "", err
	}
	return resp.Message, nil
}

func getRouter() *mux.Router {
	if router == nil {
		setup()
	}
	return router
}

// setup reinitialized the router with a fresh keydb for every test
func setup() {
	cryptor := keydb.NewAESGCMCryptor(0, []byte("testtesttesttest"))
	db := keydb.NewTempDB()
	decorators := [](func(http.HandlerFunc) http.HandlerFunc){
		AddHeader("Content-Type", "application/json"),
		AddHeader("X-Content-Type-Options", "nosniff"),
		Authentication([]auth.Provider{auth.MockGitHubProvider()}),
	}
	router = GetRouter(cryptor, db, decorators)
}

func getKeys(t *testing.T) []string {
	path := "/v0/keys/"
	keys := []string{}
	message, err := getHTTPData("GET", path, nil, &keys)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message != "" {
		t.Fatal("Code not ok for "+path, message)
	}
	return keys
}

func addKey(t *testing.T, id string, data []byte) uint64 {
	path := "/v0/keys/"
	urlData := url.Values{}
	urlData.Set("id", id)
	encodedData := base64.StdEncoding.EncodeToString(data)
	urlData.Set("data", encodedData)
	var keyID uint64
	message, err := getHTTPData("POST", path, urlData, &keyID)
	if err != nil {
		t.Fatal(err.Error())
	}

	if message != "" {
		t.Fatal(message)
	}
	return keyID
}

func getKey(t *testing.T, id string) knox.Key {
	path := "/v0/keys/" + id + "/"
	var key knox.Key
	message, err := getHTTPData("GET", path, nil, &key)
	if err != nil {
		t.Fatal(err.Error())
	}

	if message != "" {
		t.Fatal(message)
	}
	return key
}

func deleteKey(t *testing.T, id string) {
	path := "/v0/keys/" + id + "/"
	message, err := getHTTPData("DELETE", path, nil, nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	if message != "" {
		t.Fatal(message)
	}
	return
}

func getAccess(t *testing.T, id string) knox.ACL {
	path := "/v0/keys/" + id + "/access/"
	var acl knox.ACL
	message, err := getHTTPData("GET", path, nil, &acl)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message != "" {
		t.Fatal("Code not ok for "+path, message)
	}
	return acl
}

func putAccess(t *testing.T, id string, a *knox.Access) {
	path := "/v0/keys/" + id + "/access/"
	urlData := url.Values{}
	s, jsonErr := json.Marshal(a)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}
	urlData.Set("access", string(s))
	message, err := getHTTPData("PUT", path, urlData, nil)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message != "" {
		t.Fatalf("Code not ok for PUT of %s on %s: %s", urlData, path, message)
	}
	return
}

func putAccessExpectedFailure(t *testing.T, id string, a *knox.Access, expectedMessage string) {
	path := "/v0/keys/" + id + "/access/"
	urlData := url.Values{}
	s, jsonErr := json.Marshal(a)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}
	urlData.Set("access", string(s))
	message, err := getHTTPData("PUT", path, urlData, nil)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message == "" {
		t.Fatal("Access update should fail, but did not")
	}
	if !strings.Contains(message, expectedMessage) {
		t.Fatal("Access update failed, but with unexpected message:", message)
	}
	return
}

func postVersion(t *testing.T, id string, data []byte) uint64 {
	path := "/v0/keys/" + id + "/versions/"
	urlData := url.Values{}
	encodedData := base64.StdEncoding.EncodeToString(data)
	urlData.Set("data", encodedData)
	var keyID uint64
	message, err := getHTTPData("POST", path, urlData, &keyID)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message != "" {
		t.Fatal("Code not ok for "+path, message)
	}
	return keyID
}

func putVersion(t *testing.T, id string, versionID uint64, s knox.VersionStatus) {
	path := "/v0/keys/" + id + "/versions/" + strconv.FormatUint(versionID, 10) + "/"
	urlData := url.Values{}
	sStr, jsonErr := json.Marshal(s)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}
	urlData.Set("status", string(sStr))
	message, err := getHTTPData("PUT", path, urlData, nil)
	if err != nil {
		t.Fatal(err.Error())
	}
	if message != "" {
		t.Fatal("Code not ok for "+path, message)
	}
	return
}

func TestAddKeys(t *testing.T) {
	setup()
	expKeyID := "testkey"
	data := []byte("This is a test!!~ Yay weird characters ~☃~")
	keysBefore := getKeys(t)
	if keysBefore == nil || len(keysBefore) != 0 {
		t.Fatal("Expected empty array")
	}
	keyID := addKey(t, expKeyID, data)
	if keyID == 0 {
		t.Fatal("Expected keyID back")
	}
	keysAfter := getKeys(t)
	if keysAfter == nil || len(keysAfter) != 1 || keysAfter[0] != "testkey" {
		t.Fatal("Expected empty array")
	}
	key := getKey(t, expKeyID)
	if key.VersionList[0].ID != keyID {
		t.Fatal("Key ID's do not match")
	}
	if !bytes.Equal(key.VersionList[0].Data, data) {
		t.Fatal("Data is not consistant")
	}
}

func TestConcurrentAddKeys(t *testing.T) {
	// This test is to get a feel for race conditions within the http client/
	setup()
	data := []byte("This is a test!!~ Yay weird characters ~☃~")
	keysBefore := getKeys(t)
	if keysBefore == nil || len(keysBefore) != 0 {
		t.Fatal("Expected empty array")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		keyID := addKey(t, "testkey", data)
		if keyID == 0 {
			t.Error("Expected keyID back")
		}
		getKeys(t)
		key := getKey(t, "testkey")
		if key.VersionList[0].ID != keyID {
			t.Fatal("Key ID's do not match")
		}
		if !bytes.Equal(key.VersionList[0].Data, data) {
			t.Fatal("Data is not consistant")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		TestKeyAccessUpdates(t)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		keyID := "testkeyRotate"
		addKey(t, keyID, data)
		data2 := []byte("This is also a test!!~ Yay weird characters ~☃~")
		keyVersionID2 := postVersion(t, keyID, data2)
		getKey(t, keyID)
		putVersion(t, keyID, keyVersionID2, knox.Primary)
		getKey(t, keyID)
	}()
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			getKeys(t)
		}()
	}
	wg.Wait()
}

func TestKeyRotation(t *testing.T) {
	setup()
	keyID := "testkey"
	data := []byte("This is a test!!~ Yay weird characters ~☃~")
	data2 := []byte("This is also a test!!~ Yay weird characters ~☃~")
	keyVersionID := addKey(t, keyID, data)
	if keyVersionID == 0 {
		t.Fatal("Expected keyID back")
	}
	key := getKey(t, keyID)
	if len(key.VersionList) != 1 || key.VersionList[0].ID != keyVersionID {
		t.Fatal("Key ID's do not match")
	}
	if key.VersionList[0].Status != knox.Primary {
		t.Fatal("Unexpected initial version")
	}
	keyVersionID2 := postVersion(t, keyID, data2)
	if keyVersionID2 == 0 {
		t.Fatal("Expected keyID back")
	}
	key2 := getKey(t, keyID)
	if len(key2.VersionList) != 2 {
		t.Fatal("Key version list not long enough")
	}
	if key2.VersionHash == key.VersionHash {
		t.Fatal("Hashes are equivalent")
	}
	for _, k := range key2.VersionList {
		switch k.ID {
		case keyVersionID:
			if k.Status != knox.Primary {
				t.Fatal("Unexpected status for initial version: ", k.Status)
			}
		case keyVersionID2:
			if k.Status != knox.Active {
				t.Fatal("Unexpected status for rotated version: ", k.Status)
			}
		default:
			t.Fatal("Unexpected Version in VersionList")
		}
	}
	putVersion(t, keyID, keyVersionID2, knox.Primary)
	key3 := getKey(t, keyID)
	if len(key3.VersionList) != 2 {
		t.Fatal("Key version list not long enough")
	}
	if key2.VersionHash == key3.VersionHash || key3.VersionHash == key.VersionHash {
		t.Fatal("Hashes are equivalent")
	}
	for _, k := range key3.VersionList {
		switch k.ID {
		case keyVersionID:
			if k.Status != knox.Active {
				t.Fatal("Unexpected status for initial version: ", k.Status)
			}
		case keyVersionID2:
			if k.Status != knox.Primary {
				t.Fatal("Unexpected status for rotated version: ", k.Status)
			}
		default:
			t.Fatal("Unexpected Version in VersionList")
		}
	}
	putVersion(t, keyID, keyVersionID, knox.Inactive)
	key4 := getKey(t, keyID)
	if len(key4.VersionList) != 1 {
		t.Fatal("Key version list not long enough")
	}
	if key2.VersionHash == key4.VersionHash || key3.VersionHash == key4.VersionHash {
		t.Fatal("Hashes are equivalent")
	}
	if key4.VersionList[0].ID != keyVersionID2 || key4.VersionList[0].Status != knox.Primary {
		t.Fatal("Unexpected Version or status in VersionList")
	}
}

func TestKeyAccessUpdates(t *testing.T) {
	keyID := "testkeyaccess"
	data := []byte("This is a test!!~ Yay weird characters ~☃~")
	keyVersionID := addKey(t, keyID, data)
	if keyVersionID == 0 {
		t.Fatal("Expected keyID back")
	}
	acl := getAccess(t, keyID)
	if len(acl) != 1 {
		// This assumes the default access empty
		t.Fatal("Incorrect ACL length")
	}
	if acl[0].ID != "testuser" || acl[0].AccessType != knox.Admin || acl[0].Type != knox.User {
		t.Fatal("Incorrect initial ACL")
	}
	access := knox.Access{ID: "tester", Type: knox.Machine, AccessType: knox.Read}
	accessUpdate := knox.Access{ID: "tester", Type: knox.Machine, AccessType: knox.Write}
	accessDelete := knox.Access{ID: "tester", Type: knox.Machine, AccessType: knox.None}
	putAccess(t, keyID, &access)

	acl1 := getAccess(t, keyID)
	if len(acl1) != 2 {
		// This assumes the default access empty
		t.Fatal("Incorrect ACL length")
	}
	for _, a := range acl {
		switch a.ID {
		case "testuser":
		case "tester":
			if a.AccessType != access.AccessType || a.Type != access.Type {
				t.Fatal("Incorrect updated ACL")
			}
		}
	}

	putAccess(t, keyID, &accessUpdate)

	acl2 := getAccess(t, keyID)
	if len(acl2) != 2 {
		// This assumes the default access empty
		t.Fatal("Incorrect ACL length")
	}
	for _, a := range acl {
		switch a.ID {
		case "testuser":
		case "tester":
			if a.AccessType != accessUpdate.AccessType || a.Type != accessUpdate.Type {
				t.Fatal("Incorrect updated ACL")
			}
		}
	}
	putAccess(t, keyID, &accessDelete)

	acl3 := getAccess(t, keyID)
	if len(acl3) != 1 {
		// This assumes the default access empty
		t.Fatal("Incorrect ACL length")
	}
	if acl3[0].ID != "testuser" || acl3[0].AccessType != knox.Admin || acl3[0].Type != knox.User {
		t.Fatal("Incorrect initial ACL")
	}

	accessService := knox.Access{ID: "spiffe://testservice", Type: knox.Service, AccessType: knox.Read}
	putAccess(t, keyID, &accessService)
	acl4 := getAccess(t, keyID)
	if len(acl4) != 2 {
		t.Fatal("Incorrect ACL length")
	}
	for _, a := range acl {
		switch a.ID {
		case "testuser":
		case "spiffe://testservice":
			if a.AccessType != accessService.AccessType || a.Type != accessService.Type {
				t.Fatal("Incorrect updated ACL")
			}
		}
	}
}

func TestKeyAccessUpdatesWithPrincipalValidation(t *testing.T) {
	// Create a test user principal that we always reject
	invalidPrincipalID := fmt.Sprintf("%d", time.Now().UnixNano())

	customValidator := func(pt knox.PrincipalType, id string) error {
		if pt == knox.User && id == invalidPrincipalID {
			return fmt.Errorf("Invalid user: %s", id)
		}
		return nil
	}

	AddPrincipalValidator(customValidator)

	// Set up testing key
	keyID := "testkeyaccessprincipalvalidation"
	data := []byte("The Magic Words are Squeamish Ossifrage")
	keyVersionID := addKey(t, keyID, data)
	if keyVersionID == 0 {
		t.Fatal("Expected keyID back")
	}

	// Should be *valid* for user with good id
	// Note this also makes 'testuser' admin, which is required for the below
	// as testuser is the auth'd principal for all internal test calls in unit tests.
	access := knox.Access{ID: "testuser", Type: knox.User, AccessType: knox.Admin}
	putAccess(t, keyID, &access)

	// Should be *valid* for machine with bad id
	access = knox.Access{ID: invalidPrincipalID, Type: knox.Machine, AccessType: knox.Read}
	putAccess(t, keyID, &access)

	// Should be *not valid* for user with bad id
	access = knox.Access{ID: invalidPrincipalID, Type: knox.User, AccessType: knox.Read}
	putAccessExpectedFailure(t, keyID, &access, "Invalid user: "+invalidPrincipalID)

	// Should be *not valid* for user service with bad SPIFFE ID, even though
	// we don't have a special extra validator for it (validation is built-in)
	access = knox.Access{ID: "https://ahoy", Type: knox.Service, AccessType: knox.Read}
	putAccessExpectedFailure(t, keyID, &access, "Service prefix is invalid URL, must conform to 'spiffe://<domain>/<path>/' format.")
}
