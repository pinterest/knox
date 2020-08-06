package server

import (
	"reflect"
	"sort"
	"testing"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

func GetMocks() (KeyManager, knox.Principal, knox.ACL) {
	db := keydb.NewTempDB()
	cryptor := keydb.NewAESGCMCryptor(10, []byte("testtesttesttest"))
	m := NewKeyManager(cryptor, db)
	acl := knox.ACL([]knox.Access{})
	u := auth.NewUser("test", []string{})
	return m, u, acl
}

type mockPrincipal struct {
	ID string
}

func (p mockPrincipal) CanAccess(a knox.ACL, t knox.AccessType) bool {
	return true
}

func (p mockPrincipal) GetID() string {
	return p.ID
}

func TestGetAllKeyIDs(t *testing.T) {
	m, u, acl := GetMocks()
	keys, err := m.GetAllKeyIDs()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key1 := newKey("id1", acl, []byte("data"), u)
	m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key1.ID {
			t.Fatalf("%s does not match %s", keys[0], key1.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	key2 := newKey("id2", acl, []byte("data"), u)
	m.AddNewKey(&key2)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 2 {
		if keys[0] == key1.ID {
			if keys[1] != key2.ID {
				t.Fatalf("%s does not match %s", keys[1], key2.ID)
			}
		} else if keys[0] == key2.ID {
			if keys[1] != key2.ID {
				t.Fatalf("%s does not match %s", keys[1], key1.ID)
			}
		} else {
			t.Fatal("Unexpected key ID returned")
		}
	} else if len(keys) != 1 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	err = m.DeleteKey(key1.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key2.ID {
			t.Fatalf("%s does not match %s", keys[0], key2.ID)
		}
	} else if len(keys) != 2 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}
}

func TestGetUpdatedKeyIDs(t *testing.T) {
	m, u, acl := GetMocks()
	keys, err := m.GetUpdatedKeyIDs(map[string]string{})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key1 := newKey("id1", acl, []byte("data"), u)
	m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key1.ID: "NOT_THE_HASH"})
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key1.ID {
			t.Fatalf("%s does not match %s", keys[0], key1.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key1.ID: key1.VersionHash})
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key2 := newKey("id2", acl, []byte("data"), u)
	m.AddNewKey(&key2)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key2.ID: "NOT_THE_HASH"})
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key2.ID {
			t.Fatalf("%s does not match %s", keys[0], key2.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key2.ID: "NOT_THE_HASH", key1.ID: "NOT_THE_HASH"})
	if len(keys) != 2 {
		t.Fatalf("Expect 2 keys not %d", len(keys))
	}
	if keys[0] == key1.ID {
		if keys[1] != key2.ID {
			t.Fatalf("%s does not match %s", keys[1], key2.ID)
		}
	} else if keys[0] == key2.ID {
		if keys[1] != key1.ID {
			t.Fatalf("%s does not match %s", keys[1], key1.ID)
		}
	} else {
		t.Fatal("Unexpected key ID returned")
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key2.ID: key2.VersionHash, key1.ID: "NOT_THE_HASH"})
	if len(keys) != 1 {
		t.Fatalf("Expect 1 key not %d", len(keys))
	}
	if keys[0] != key1.ID {
		t.Fatalf("%s does not match %s", keys[0], key1.ID)
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key2.ID: key2.VersionHash, key1.ID: key1.VersionHash})
	if len(keys) != 0 {
		t.Fatal("expected no keys")
	}

}

func TestAddNewKey(t *testing.T) {
	m, u, acl := GetMocks()
	key1 := newKey("id1", acl, []byte("data"), u)

	key, err := m.GetKey(key1.ID, knox.Active)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if !reflect.DeepEqual(key, &key1) {
		t.Fatal("keys are not equal")
	}

	pKey, err := m.GetKey(key1.ID, knox.Primary)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	aKey, err := m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if !reflect.DeepEqual(pKey, aKey) {
		t.Fatal("keys are not equal")
	}

	iKey, err := m.GetKey(key1.ID, knox.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if !reflect.DeepEqual(pKey, iKey) {
		t.Fatal("keys are not equal")
	}
	if !reflect.DeepEqual(iKey, aKey) {
		t.Fatal("keys are not equal")
	}

	err = m.DeleteKey(key1.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err == nil {
		t.Fatal("Should be an error")
	}
}

func TestUpdateAccess(t *testing.T) {
	m, u, acl := GetMocks()
	key1 := newKey("id1", acl, []byte("data"), u)
	access := knox.Access{Type: knox.User, ID: "grootan", AccessType: knox.Read}
	access2 := knox.Access{Type: knox.UserGroup, ID: "group", AccessType: knox.Write}
	access3 := knox.Access{Type: knox.Machine, ID: "machine", AccessType: knox.Read}
	err := m.UpdateAccess(key1.ID, access)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	err = m.UpdateAccess(key1.ID, access)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = m.UpdateAccess(key1.ID, access2, access3)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err := m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(key.ACL) != 4 {
		t.Fatalf("%d acl rules instead of expected 4", len(key.ACL))
	}
	for _, a := range key.ACL {
		switch a.ID {
		case access.ID:
			if access.Type != a.Type {
				t.Fatalf("%d does not equal %d", access.Type, a.Type)
			}
			if access.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access.AccessType, a.AccessType)
			}
		case access2.ID:
			if access2.Type != a.Type {
				t.Fatalf("%d does not equal %d", access2.Type, a.Type)
			}
			if access2.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access2.AccessType, a.AccessType)
			}
		case access3.ID:
			if access3.Type != a.Type {
				t.Fatalf("%d does not equal %d", access3.Type, a.Type)
			}
			if access3.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access3.AccessType, a.AccessType)
			}
		case u.GetID():
			continue
		default:
			t.Fatalf("unknown acl value for key %v", a)
		}
	}
}

func TestAddUpdateVersion(t *testing.T) {
	m, u, acl := GetMocks()
	var key *knox.Key
	key1 := newKey("id1", acl, []byte("data"), u)
	kv := newKeyVersion([]byte("data2"), knox.Active)
	access := knox.Access{Type: knox.User, ID: "grootan", AccessType: knox.Read}
	err := m.UpdateAccess(key1.ID, access)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if !reflect.DeepEqual(key, &key1) {
		t.Fatal("keys are not equal")
	}

	err = m.AddVersion(key1.ID, &kv)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if len(key.VersionList) != 2 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 2)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	sort.Sort(key.VersionList)
	sort.Sort(key1.VersionList)
	for _, kv1 := range key.VersionList {
		if kv1.Status == knox.Primary {
			if !reflect.DeepEqual(kv1, key1.VersionList[0]) {
				t.Fatal("primary versions are not equal")
			}
		}
		if kv1.Status == knox.Active {
			if !reflect.DeepEqual(kv1, kv) {
				t.Fatal("active versions are not equal")
			}
		}
		if kv1.Status == knox.Inactive {
			t.Fatal("No key versions should be inactive")
		}
	}

	err = m.UpdateVersion(key1.ID, kv.ID, knox.Primary)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	if len(key.VersionList) != 2 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 2)
	}
	sort.Sort(key.VersionList)
	kv1 := key.VersionList[0]
	if kv1.Status != knox.Primary {
		t.Fatalf("%d does equal %d", kv1.Status, knox.Primary)
	}
	if kv1.ID != kv.ID {
		t.Fatalf("%d does equal %d", kv1.ID, kv.ID)
	}
	if string(kv1.Data) != string(kv.Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(kv.Data))
	}
	if kv1.CreationTime != kv.CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, kv.CreationTime)
	}

	kv1 = key.VersionList[1]
	if kv1.Status != knox.Active {
		t.Fatalf("%d does equal %d", kv1.Status, knox.Primary)
	}
	if kv1.ID != key1.VersionList[0].ID {
		t.Fatalf("%d does equal %d", kv1.ID, key1.VersionList[0].ID)
	}
	if string(kv1.Data) != string(key1.VersionList[0].Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(key1.VersionList[0].Data))
	}
	if kv1.CreationTime != key1.VersionList[0].CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, key1.VersionList[0].CreationTime)
	}

	err = m.UpdateVersion(key1.ID, key1.VersionList[0].ID, knox.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	if len(key.VersionList) != 1 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 1)
	}
	kv1 = key.VersionList[0]
	if kv1.Status != knox.Primary {
		t.Fatalf("%d does equal %d", kv1.Status, knox.Primary)
	}
	if kv1.ID != kv.ID {
		t.Fatalf("%d does equal %d", kv1.ID, kv.ID)
	}
	if string(kv1.Data) != string(kv.Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(kv.Data))
	}
	if kv1.CreationTime != kv.CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, kv.CreationTime)
	}
}

func TestGetInactiveKeyVersions(t *testing.T) {
	m, u, acl := GetMocks()

	keyOrig := newKey("id1", acl, []byte("data"), u)
	kv := newKeyVersion([]byte("data2"), knox.Active)

	// Create key and add version so we have two versions
	err := m.AddNewKey(&keyOrig)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	err = m.AddVersion(keyOrig.ID, &kv)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	// Get active versions and deactivate one of them
	key, err := m.GetKey(keyOrig.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	kvID0 := key.VersionList[0].ID
	kvID1 := key.VersionList[1].ID

	// Deactivate one of these versions
	err = m.UpdateVersion(keyOrig.ID, kvID1, knox.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	// Reading active key versions should now list only one version
	key, err = m.GetKey(keyOrig.ID, knox.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	if len(key.VersionList) != 1 {
		t.Fatalf("Wanted one key version, got: %d", len(key.VersionList))
	}
	if key.VersionList[0].ID != kvID0 {
		t.Fatalf("Inactive key id was listed as ctive")
	}

	// Reading active/inactive key versions should now list both
	key, err = m.GetKey(keyOrig.ID, knox.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	if len(key.VersionList) != 2 {
		t.Fatalf("Wanted two key versions, got: %d", len(key.VersionList))
	}
}
