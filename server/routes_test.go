package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

func makeDB() (KeyManager, *keydb.TempDB) {
	db := &keydb.TempDB{}
	cryptor := keydb.NewAESGCMCryptor(0, []byte("testtesttesttest"))
	m := NewKeyManager(cryptor, db)
	return m, db
}

func TestGetKeys(t *testing.T) {
	m, db := makeDB()
	u := auth.NewUser("testuser", []string{})

	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}
	_, err = postKeysHandler(m, u, map[string]string{"id": "a2", "data": "Mg=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}
	_, err = postKeysHandler(m, u, map[string]string{"id": "a3", "data": "Mw=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	i, err := getKeysHandler(m, u, nil)
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}
	switch d := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case []string:
		if len(d) != 3 {
			t.Fatalf("length of return should be 3 not %d", len(d))
		}
		if d[0] != "a1" {
			t.Fatalf("Expected first value to be a1 not %s", d[0])
		}
		if d[1] != "a2" {
			t.Fatalf("Expected first value to be a2 not %s", d[1])
		}
		if d[2] != "a3" {
			t.Fatalf("Expected first value to be a3 not %s", d[2])
		}
	}

	i, err = getKeysHandler(m, u, map[string]string{"queryString": "a1=NOHASH"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}
	switch d := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case []string:
		if len(d) != 1 {
			t.Fatalf("length of return should be 1 not %d", len(d))
		}
		if d[0] != "a1" {
			t.Fatalf("Expected first value to be a1 not %s", d[0])
		}
	}

	db.SetError(fmt.Errorf("Test Error!"))
	_, err = getKeysHandler(m, u, map[string]string{"queryString": "a1=NOHASH"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = getKeysHandler(m, u, nil)
	if err == nil {
		t.Fatal("Expected err")
	}
}

func TestPostKeys(t *testing.T) {
	m, db := makeDB()
	machine := auth.NewMachine("MrRoboto")
	_, err := postKeysHandler(m, machine, map[string]string{"id": "a1", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	u := auth.NewUser("testuser", []string{})

	_, err = postKeysHandler(m, u, map[string]string{"data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ==", "acl": "NOTJSON"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a1", "data": "NotBAse64.."})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a$#", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	i, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postKeysHandler(m, u, map[string]string{"id": "a1", "data": ""})
	if err == nil {
		t.Fatal("Expected err")
	}

	j, err := postKeysHandler(m, u, map[string]string{"id": "a2", "data": "MQ==", "acl": "[]"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	switch q := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case uint64:
		switch r := j.(type) {
		default:
			t.Fatal("Unexpected type of response")
		case uint64:
			if q == r {
				t.Fatalf("%d should not equal %d", q, r)
			}
		}
	}

	db.SetError(fmt.Errorf("Test Error"))
	_, err = postKeysHandler(m, u, map[string]string{"id": "a3", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err")
	}
}

func TestPostKeysServiceWithAuthorizer(t *testing.T) {
	m, _ := makeDB()
	svc := auth.NewService("example.com", "service/test-svc/v1")
	machine := auth.NewMachine("test-machine")

	// Without any authorizer installed, non-user principals are rejected
	// (preserving the pre-existing user-only default).
	_, err := postKeysHandler(m, svc, map[string]string{"id": "test:project:key1", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err when no service authorizer is installed")
	}

	authz := &PrefixServiceKeyCreationAuthorizer{}
	if addErr := authz.AddPolicy(ServiceKeyCreationPolicy{
		SpiffePrefix: "spiffe://example.com/service/test-svc/",
		KeyPrefix:    "test:project:",
		Owner:        knox.Access{ID: "test-owners", Type: knox.UserGroup},
		Metadata:     map[string]string{"project": "test-project"},
	}); addErr != nil {
		t.Fatalf("AddPolicy returned unexpected error: %v", addErr)
	}
	SetServiceKeyCreationAuthorizer(authz)
	defer SetServiceKeyCreationAuthorizer(nil)

	// Matching service + key prefix succeeds and the owner is recorded as admin.
	i, err := postKeysHandler(m, svc, map[string]string{"id": "test:project:key1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("Expected success for matching policy, got: %+v", err)
	}
	if _, ok := i.(uint64); !ok {
		t.Fatalf("Expected uint64 version id, got %T", i)
	}
	k, kerr := m.GetKey("test:project:key1", knox.Active)
	if kerr != nil {
		t.Fatalf("Could not fetch newly created key: %v", kerr)
	}
	foundOwnerAdmin := false
	for _, a := range k.ACL {
		if a.ID == "test-owners" && a.Type == knox.UserGroup && a.AccessType == knox.Admin {
			foundOwnerAdmin = true
		}
	}
	if !foundOwnerAdmin {
		t.Fatalf("Expected owner 'test-owners' to be Admin on ACL, got %+v", k.ACL)
	}

	// Non-matching key prefix is rejected.
	_, err = postKeysHandler(m, svc, map[string]string{"id": "other:prefix:key", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err for non-matching key prefix")
	}

	// Non-matching SPIFFE is rejected.
	otherSvc := auth.NewService("example.com", "service/other-svc/v1")
	_, err = postKeysHandler(m, otherSvc, map[string]string{"id": "test:project:key2", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err for non-matching SPIFFE")
	}

	// Machine principals are always rejected.
	_, err = postKeysHandler(m, machine, map[string]string{"id": "test:project:key3", "data": "MQ=="})
	if err == nil {
		t.Fatal("Expected err for machine principal")
	}
}

func TestPrefixServiceKeyCreationAuthorizerRequiresOwner(t *testing.T) {
	authz := &PrefixServiceKeyCreationAuthorizer{}
	err := authz.AddPolicy(ServiceKeyCreationPolicy{
		SpiffePrefix: "spiffe://example.com/service/test-svc/",
		KeyPrefix:    "test:project:",
	})
	if err == nil {
		t.Fatal("Expected AddPolicy to reject a policy with no Owner")
	}
}

func TestPrefixServiceKeyCreationAuthorizerValidatesSpiffePrefix(t *testing.T) {
	owner := knox.Access{ID: "test-owners", Type: knox.UserGroup}

	cases := []struct {
		name   string
		prefix string
	}{
		{"empty", ""},
		{"not a spiffe url", "http://example.com/service/"},
		{"missing trailing slash", "spiffe://example.com/service/test-svc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authz := &PrefixServiceKeyCreationAuthorizer{}
			err := authz.AddPolicy(ServiceKeyCreationPolicy{
				SpiffePrefix: tc.prefix,
				KeyPrefix:    "test:project:",
				Owner:        owner,
			})
			if err == nil {
				t.Fatalf("Expected AddPolicy to reject SpiffePrefix %q", tc.prefix)
			}
		})
	}
}

func TestGetKey(t *testing.T) {
	m, _ := makeDB()
	machine := auth.NewMachine("MrRoboto")

	u := auth.NewUser("testuser", []string{})
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	i, err := getKeyHandler(m, u, map[string]string{"keyID": "a1"})
	switch k := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case *knox.Key:
		if k.ID != "a1" {
			t.Fatalf("Expected ID to be a1 not %s", k.ID)
		}
		if len(k.ACL) != 0 {
			t.Fatalf("Expected key acl to be empty")
		}
		if len(k.VersionList) != 1 {
			t.Fatalf("Expected len to be 1 not %d", len(k.VersionList))
		}
		if string(k.VersionList[0].Data) != "1" {
			t.Fatalf("Expected ID to be a1 not %s", string(k.VersionList[0].Data))
		}
	}

	i, err = getKeyHandler(m, u, map[string]string{"keyID": "a1", "status": "\"Inactive\""})
	switch k := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case *knox.Key:
		if k.ID != "a1" {
			t.Fatalf("Expected ID to be a1 not %s", k.ID)
		}
		if len(k.ACL) != 0 {
			t.Fatalf("Expected key acl to be empty")
		}
		if len(k.VersionList) != 1 {
			t.Fatalf("Expected len to be 1 not %d", len(k.VersionList))
		}
		if string(k.VersionList[0].Data) != "1" {
			t.Fatalf("Expected ID to be a1 not %s", string(k.VersionList[0].Data))
		}
	}

	i, err = getKeyHandler(m, u, map[string]string{"keyID": "a1", "status": "\"Primary\""})
	switch k := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case *knox.Key:
		if k.ID != "a1" {
			t.Fatalf("Expected ID to be a1 not %s", k.ID)
		}
		if len(k.ACL) != 0 {
			t.Fatalf("Expected key acl to be empty")
		}
		if len(k.VersionList) != 1 {
			t.Fatalf("Expected len to be 1 not %d", len(k.VersionList))
		}
		if string(k.VersionList[0].Data) != "1" {
			t.Fatalf("Expected ID to be a1 not %s", string(k.VersionList[0].Data))
		}
	}

	i, err = getKeyHandler(m, u, map[string]string{"keyID": "a1", "status": "AJSDFLKJlks"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = getKeyHandler(m, machine, map[string]string{"keyID": "NOTAKEY"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = getKeyHandler(m, machine, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}
}

func TestDeleteKey(t *testing.T) {
	m, db := makeDB()
	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = deleteKeyHandler(m, u, map[string]string{"keyID": "NOTAKEY"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = deleteKeyHandler(m, machine, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(fmt.Errorf("Test Error"))
	_, err = deleteKeyHandler(m, u, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(nil)
	_, err = deleteKeyHandler(m, u, map[string]string{"keyID": "a1"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = deleteKeyHandler(m, u, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = getKeyHandler(m, u, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}
}

func TestGetAccess(t *testing.T) {
	m, _ := makeDB()
	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = getAccessHandler(m, machine, map[string]string{"keyID": "a1"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = getAccessHandler(m, u, map[string]string{"keyID": "NOTAKEY"})
	if err == nil {
		t.Fatal("Expected err")
	}

	i, err := getAccessHandler(m, u, map[string]string{"keyID": "a1"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	switch acl := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case knox.ACL:
		if len(acl) != 1 {
			t.Fatalf("Length of acl is %d not 1", len(acl))
		}
		if acl[0].ID != "testuser" {
			t.Fatalf("Expected acl value to be testuser not %s", acl[0].ID)
		}

	}
}

func TestPutAccess(t *testing.T) {
	m, db := makeDB()
	access := []knox.Access{{Type: knox.Machine, ID: "MrRoboto", AccessType: knox.Read}}
	accessJSON, jerr := json.Marshal(&access)
	if jerr != nil {
		t.Fatalf("%+v is not nil", jerr)
	}

	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "acl": "NotJSON"})
	if err == nil {
		t.Fatal("Expected err")
	}
	_, err = putAccessHandler(m, u, map[string]string{"keyID": "NOTAKEY", "acl": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putAccessHandler(m, machine, map[string]string{"keyID": "a1", "acl": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "acl": string(accessJSON)})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	db.SetError(fmt.Errorf("Test Error"))
	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "acl": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(nil)
	_, err = getKeyHandler(m, machine, map[string]string{"keyID": "a1"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	//Tests for setting ACLs with empty machinePrefix
	//Should return error when used with AccessType Read,Write, or Admin
	//Should return success when used with AccessType None(useful for revoking such existing ACLs)
	accessTypes := []knox.AccessType{knox.None, knox.Read, knox.Write, knox.Admin}
	for _, accessType := range accessTypes {
		access = []knox.Access{{Type: knox.MachinePrefix, ID: "", AccessType: accessType}}
		accessJSON, jerr = json.Marshal(&access)
		if jerr != nil {
			t.Fatalf("%+v is not nil", jerr)
		}
		_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "acl": string(accessJSON)})
		if err == nil && accessType != knox.None {
			t.Fatal("Expected err")
		} else if err != nil && accessType == knox.None {
			t.Fatalf("%+v is not nil", err)
		}
	}

}

func TestLegacyPutAccess(t *testing.T) {
	m, db := makeDB()
	access := &knox.Access{Type: knox.Machine, ID: "MrRoboto", AccessType: knox.Read}
	accessJSON, jerr := json.Marshal(access)
	if jerr != nil {
		t.Fatalf("%+v is not nil", jerr)
	}

	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "access": "NotJSON"})
	if err == nil {
		t.Fatal("Expected err")
	}
	_, err = putAccessHandler(m, u, map[string]string{"keyID": "NOTAKEY", "access": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putAccessHandler(m, machine, map[string]string{"keyID": "a1", "access": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "access": string(accessJSON)})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	db.SetError(fmt.Errorf("Test Error"))
	_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "access": string(accessJSON)})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(nil)
	_, err = getKeyHandler(m, machine, map[string]string{"keyID": "a1"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	//Tests for setting ACLs with empty machinePrefix
	//Should return error when used with AccessType Read,Write, or Admin
	//Should return success when used with AccessType None(useful for revoking such existing ACLs)
	accessTypes := []knox.AccessType{knox.None, knox.Read, knox.Write, knox.Admin}
	for _, accessType := range accessTypes {
		access = &knox.Access{Type: knox.MachinePrefix, ID: "", AccessType: accessType}
		accessJSON, jerr = json.Marshal(access)
		if jerr != nil {
			t.Fatalf("%+v is not nil", jerr)
		}
		_, err = putAccessHandler(m, u, map[string]string{"keyID": "a1", "access": string(accessJSON)})
		if err == nil && accessType != knox.None {
			t.Fatal("Expected err")
		} else if err != nil && accessType == knox.None {
			t.Fatalf("%+v is not nil", err)
		}
	}
}

func TestPostVersion(t *testing.T) {
	m, db := makeDB()
	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	j, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = postVersionHandler(m, u, map[string]string{"keyID": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postVersionHandler(m, u, map[string]string{"keyID": "a1", "data": "NOTBASE64"})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postVersionHandler(m, u, map[string]string{"keyID": "a1", "data": ""})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postVersionHandler(m, u, map[string]string{"keyID": "NOTAKEYID", "data": "Mg=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = postVersionHandler(m, machine, map[string]string{"keyID": "a1", "data": "Mg=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(fmt.Errorf("WAHAHAHA error"))

	_, err = postVersionHandler(m, u, map[string]string{"keyID": "a1", "data": "Mg=="})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(nil)
	i, err := postVersionHandler(m, u, map[string]string{"keyID": "a1", "data": "Mg=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	switch q := i.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case uint64:
		switch r := j.(type) {
		default:
			t.Fatal("Unexpected type of response")
		case uint64:
			if q == r {
				t.Fatalf("%d should not equal %d", q, r)
			}
		}
	}
}

func TestPutVersions(t *testing.T) {
	m, db := makeDB()
	u := auth.NewUser("testuser", []string{})
	machine := auth.NewMachine("MrRoboto")
	i, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": "MQ=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}
	j, err := postVersionHandler(m, u, map[string]string{"keyID": "a1", "data": "Mg=="})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	old, ok := i.(uint64)
	if !ok {
		t.Fatal("Version should be a uint64")
	}
	n, ok := j.(uint64)
	if !ok {
		t.Fatal("Version should be a uint64")
	}
	oldString := fmt.Sprintf("%d", old)
	newString := fmt.Sprintf("%d", n)

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `NOTASTATUS`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": "NOTANINT", "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "NOTAKEY", "versionID": newString, "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, machine, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(fmt.Errorf("WAHAHAHA error"))
	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	db.SetError(nil)
	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Primary"`})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": oldString, "status": `"Inactive"`})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": oldString, "status": `"Primary"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Active"`})
	if err == nil {
		t.Fatal("Expected err")
	}

	_, err = putVersionsHandler(m, u, map[string]string{"keyID": "a1", "versionID": newString, "status": `"Inactive"`})
	if err == nil {
		t.Fatal("Expected err")
	}

}

func TestAuthorizeRequest(t *testing.T) {
	type input struct {
		Key        *knox.Key
		Principal  knox.Principal
		AccessType knox.AccessType
	}

	type testCase struct {
		Name               string
		Input              input
		CallBackImpl       func(input knox.AccessCallbackInput) (bool, error)
		ExpectedAuthorized bool
		ExpectedError      error
	}

	triggerCallBackInput := input{
		Key:        &knox.Key{ID: "test", ACL: knox.ACL{{ID: "test", AccessType: knox.Read, Type: knox.User}}},
		Principal:  auth.NewUser("test", []string{"returntrue"}),
		AccessType: knox.Write,
	}

	testCases := []testCase{
		{
			Name:  "AccessCallback returns true",
			Input: triggerCallBackInput,
			CallBackImpl: func(input knox.AccessCallbackInput) (bool, error) {
				return true, nil
			},
			ExpectedAuthorized: true,
			ExpectedError:      nil,
		},
		{
			Name:  "AccessCallback returns false",
			Input: triggerCallBackInput,
			CallBackImpl: func(input knox.AccessCallbackInput) (bool, error) {
				return false, nil
			},
			ExpectedAuthorized: false,
			ExpectedError:      nil,
		},
		{
			Name:  "AccessCallback returns false with valid input",
			Input: triggerCallBackInput,
			CallBackImpl: func(input knox.AccessCallbackInput) (bool, error) {
				return input.AccessType == knox.Write && input.Key.ACL[0].ID == "test" && input.Key.ACL[0].Type == knox.User, nil
			},
			ExpectedAuthorized: true,
			ExpectedError:      nil,
		},
		{
			Name:               "AccessCallback is nil",
			Input:              triggerCallBackInput,
			CallBackImpl:       nil,
			ExpectedAuthorized: false,
			ExpectedError:      nil,
		},
		{
			Name:  "AccessCallback panics",
			Input: triggerCallBackInput,
			CallBackImpl: func(input knox.AccessCallbackInput) (bool, error) {
				panic("intentional panic")
			},
			ExpectedAuthorized: false,
			ExpectedError:      fmt.Errorf("recovered from panic in access callback: intentional panic"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			defer SetAccessCallback(nil)

			SetAccessCallback(tc.CallBackImpl)
			authorized, err := authorizeRequest(tc.Input.Key, tc.Input.Principal, tc.Input.AccessType)
			if err != nil {
				if err.Error() == tc.ExpectedError.Error() {
					if authorized != tc.ExpectedAuthorized {
						t.Fatalf("Expected %v, got %v", tc.ExpectedAuthorized, authorized)
					}
				} else {
					t.Fatalf("Got err: %v", err)
				}
			}
			if authorized != tc.ExpectedAuthorized {
				t.Fatalf("Expected %v, got %v", tc.ExpectedAuthorized, authorized)
			}
		})
	}
}
