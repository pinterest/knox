package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

const Number1 = "1"
// I.e. b64encode("1")
const Number1B64Encoded = "MQ=="

func makeDB() (KeyManager, *keydb.TempDB) {
	db := &keydb.TempDB{}
	cryptor := keydb.NewAESGCMCryptor(0, []byte("testtesttesttest"))
	m := NewKeyManager(cryptor, db)
	return m, db
}

func TestGetKeys(t *testing.T) {
	m, db := makeDB()
	u := auth.NewUser("testuser", []string{})

	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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

	// Machine tests
	machine := auth.NewMachine("MrRoboto")
	// Machines cannot create keys
	_, err := postKeysHandler(m, machine, map[string]string{"id": "a1", "data": Number1B64Encoded})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.UnauthorizedCode {
		t.Fatalf("Expected %v and got %v", knox.UnauthorizedCode, err.Subcode)
	} else if err.Message != "Must be a user (or SPIFFE if multiple human admins in ACL) to create keys, principal is MrRoboto" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Service tests
	serviceA := auth.NewService("example.com", "serviceA")
	// ACL JSON but still Invalid
	_, err = postKeysHandler(m, serviceA, map[string]string{"id": "a1", "data": Number1B64Encoded, "acl": `[{"type":"foo","id":"bar","access":"test"}]`})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.BadAclCode {
		t.Fatalf("Expected %v and got %v", knox.BadAclCode, err.Subcode)
	} else if err.Message != "json: Invalid AccessType to convert" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}
	// Valid ACL but no human admin
	_, err = postKeysHandler(m, serviceA, map[string]string{"id": "a1", "data": Number1B64Encoded, "acl": `[{"type":"User","id":"testuser","access":"Write"}, {"type":"Machine","id":"testmachine1","access":"Admin"}]`})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.NoMultipleHumanAdminsInAclCode {
		t.Fatalf("Expected %v and got %v", knox.NoMultipleHumanAdminsInAclCode, err.Subcode)
	} else if err.Message != "Parameter 'acl' does not have multiple human admins" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}
	// Valid ACL with only 1 human admin
	_, err = postKeysHandler(m, serviceA, map[string]string{"id": "a0", "data": Number1B64Encoded, "acl": `[{"type":"User","id":"testuser","access":"Admin"}, {"type":"Machine","id":"testmachine1","access":"Admin"}]`})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.NoMultipleHumanAdminsInAclCode {
		t.Fatalf("Expected %v and got %v", knox.NoMultipleHumanAdminsInAclCode, err.Subcode)
	} else if err.Message != "Parameter 'acl' does not have multiple human admins" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}
	// Valid ACL with 2 human admins
	_, err = postKeysHandler(m, serviceA, map[string]string{"id": "a0", "data": Number1B64Encoded, "acl": `[{"type":"User","id":"testuser","access":"Admin"}, {"type":"User","id":"testuser2","access":"Admin"}]`})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	// User tests
	testuser := auth.NewUser("testuser", []string{})

	// No id
	_, err = postKeysHandler(m, testuser, map[string]string{"data": Number1B64Encoded})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.NoKeyIDCode {
		t.Fatalf("Expected %v and got %v", knox.NoKeyIDCode, err.Subcode)
	} else if err.Message != "Missing parameter 'id'" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// No data
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1"})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.NoKeyDataCode {
		t.Fatalf("Expected %v and got %v", knox.NoKeyDataCode, err.Subcode)
	} else if err.Message != "Missing parameter 'data'" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// ACL not JSON
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": Number1B64Encoded, "acl": "NOTJSON"})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.BadAclCode {
		t.Fatalf("Expected %v and got %v", knox.BadAclCode, err.Subcode)
	} else if err.Message != "invalid character 'N' looking for beginning of value" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// ACL JSON but still Invalid
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": Number1B64Encoded, "acl": `[{"type":"foo","id":"bar","access":"test"}]`})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.BadAclCode {
		t.Fatalf("Expected %v and got %v", knox.BadAclCode, err.Subcode)
	} else if err.Message != "json: Invalid AccessType to convert" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Base64 decode error on Data
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": "NotBAse64.."})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.BadRequestDataCode {
		t.Fatalf("Expected %v and got %v", knox.BadRequestDataCode, err.Subcode)
	} else if err.Message != "illegal base64 data at input byte 9" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Invalid KeyID
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a$#", "data": Number1B64Encoded})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.BadKeyFormatCode {
		t.Fatalf("Expected %v and got %v", knox.BadKeyFormatCode, err.Subcode)
	} else if err.Message != "KeyID includes unsupported characters a$#" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Make a1 key
	a1KeyID, err := postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": Number1B64Encoded})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	// Key already exists
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": Number1B64Encoded})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.KeyIdentifierExistsCode {
		t.Fatalf("Expected %v and got %v", knox.KeyIdentifierExistsCode, err.Subcode)
	} else if err.Message != "Key a1 already exists" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Empty data
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a1", "data": ""})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.NoKeyDataCode {
		t.Fatalf("Expected %v and got %v", knox.NoKeyDataCode, err.Subcode)
	} else if err.Message != "Parameter 'data' is empty" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}

	// Make a2 key
	a2KeyID, err := postKeysHandler(m, testuser, map[string]string{"id": "a2", "data": Number1B64Encoded, "acl": "[]"})
	if err != nil {
		t.Fatalf("%+v is not nil", err)
	}

	switch q := a1KeyID.(type) {
	default:
		t.Fatal("Unexpected type of response")
	case uint64:
		switch r := a2KeyID.(type) {
		default:
			t.Fatal("Unexpected type of response")
		case uint64:
			if q == r {
				t.Fatalf("%d should not equal %d", q, r)
			}
		}
	}

	db.SetError(fmt.Errorf("Test Error"))
	_, err = postKeysHandler(m, testuser, map[string]string{"id": "a3", "data": Number1B64Encoded})
	if err == nil {
		t.Fatal("Expected err")
	} else if err.Subcode != knox.InternalServerErrorCode {
		t.Fatalf("Expected %v and got %v", knox.InternalServerErrorCode, err.Subcode)
	} else if err.Message != "Test Error" {
		t.Fatalf("Unexpected error message: %v", err.Message)
	}
}

func TestGetKey(t *testing.T) {
	m, _ := makeDB()
	machine := auth.NewMachine("MrRoboto")

	u := auth.NewUser("testuser", []string{})
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
		if string(k.VersionList[0].Data) != Number1 {
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
		if string(k.VersionList[0].Data) != Number1 {
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
		if string(k.VersionList[0].Data) != Number1 {
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
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
	_, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
	j, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
	i, err := postKeysHandler(m, u, map[string]string{"id": "a1", "data": Number1B64Encoded})
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
