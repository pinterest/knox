package knox_test

import (
	"encoding/json"
	"testing"

	. "github.com/pinterest/knox"
)

func TestKeyVersionListHash(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Active, 10}
	versions := []KeyVersion{v1, v2, v3}
	statuses := []VersionStatus{Active, Inactive}
	hashes := map[string]string{}
	for i := range versions {
		versions[i].Status = Primary
		for _, s1 := range statuses {
			versions[(i+1)%3].Status = s1
			for _, s2 := range statuses {
				versions[(i+2)%3].Status = s2
				h := KeyVersionList([]KeyVersion{versions[0], versions[1], versions[2]}).Hash()
				text, _ := json.Marshal(versions)
				if _, match := hashes[h]; match {
					t.Error("hashes match: " + string(text) + " == " + hashes[h])
				}
				hashes[h] = string(text)
			}
		}
	}
}

func TestKeyVersionListUpdate(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Inactive, 10}
	kvl := KeyVersionList([]KeyVersion{v1, v2, v3})
	_, Primary2PrimaryErr := kvl.Update(v1.ID, Primary)
	if Primary2PrimaryErr == nil {
		t.Error("Primary can't go to Primary")
	}
	_, Primary2ActiveErr := kvl.Update(v1.ID, Active)
	if Primary2ActiveErr == nil {
		t.Error("Primary can go to Active")
	}
	_, Primary2InActiveErr := kvl.Update(v1.ID, Inactive)
	if Primary2InActiveErr == nil {
		t.Error("Primary can go to Inactive")
	}
	_, Active2ActiveErr := kvl.Update(v2.ID, Active)
	if Active2ActiveErr == nil {
		t.Error("Active can go to Active")
	}
	_, inActive2InActiveErr := kvl.Update(v3.ID, Inactive)
	if inActive2InActiveErr == nil {
		t.Error("InActive can go to Inactive")
	}
	_, inActive2PrimaryErr := kvl.Update(v3.ID, Primary)
	if inActive2PrimaryErr == nil {
		t.Error("InActive can go to Primary")
	}
	kvl, inActive2ActiveErr := kvl.Update(v3.ID, Active)
	if inActive2ActiveErr != nil {
		t.Error("InActive can't go to Active")
	}
	for _, kv := range kvl {
		if kv.ID == v1.ID && kv.Status != Primary {
			t.Error("Wrong type on v1")
		}
		if kv.ID == v2.ID && kv.Status != Active {
			t.Error("Wrong type on v2")
		}
		if kv.ID == v3.ID && kv.Status != Active {
			t.Error("Wrong type on v3")
		}
	}
	kvl, Active2InativeErr := kvl.Update(v3.ID, Inactive)
	if Active2InativeErr != nil {
		t.Error("Active can't go to Inactive")
	}

	kvl, Active2PrimaryErr := kvl.Update(v2.ID, Primary)
	if Active2PrimaryErr != nil {
		t.Error("Active can't go to Primary")
	}
	for _, kv := range kvl {
		if kv.ID == v1.ID && kv.Status != Active {
			t.Error("Wrong type on v1")
		}
		if kv.ID == v2.ID && kv.Status != Primary {
			t.Error("Wrong type on v2")
		}
		if kv.ID == v3.ID && kv.Status != Inactive {
			t.Error("Wrong type on v3")
		}
	}

	_, dneErr := kvl.Update(2387498237, Active)
	if dneErr != ErrKeyVersionNotFound {
		t.Error("Expected version to not exist")
	}
}

func marshalUnmarshal(t *testing.T, in json.Marshaler, out json.Unmarshaler) {
	s, mErr := in.MarshalJSON()
	if mErr != nil {
		t.Error(mErr)
	}
	uErr := out.UnmarshalJSON(s)
	if uErr != nil {
		t.Error(uErr)
	}
}
func TestAccessTypeMarshaling(t *testing.T) {
	for _, in := range []AccessType{Read, Write, Admin, None} {
		var out AccessType
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}
	}
	var invalid AccessType
	invalid = 12938798732 // This is not currently an AccessType
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr == nil {
		t.Error("Unmarshaled invalid string")
	}
}
func TestPrincipalTypeMarshaling(t *testing.T) {
	for _, in := range []PrincipalType{User, UserGroup, Machine, MachinePrefix, Service} {
		var out PrincipalType
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}

	}
	var invalid PrincipalType
	invalid = 12938798732 // This is not currently an PrincipalType
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr != nil {
		t.Error("Did not unmarshal invalid string")
	}
	if invalid != -1 {
		t.Error("Unmarshalling invalid Principal type should result in -1")
	}

}
func TestVersionStatusMarshaling(t *testing.T) {
	for _, in := range []VersionStatus{Primary, Active, Inactive} {
		var out VersionStatus
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}

	}
	var invalid VersionStatus
	invalid = 12938798732 // This is not currently an VersionStatus
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr == nil {
		t.Error("Unmarshaled invalid string")
	}
}

func TestACLValidate(t *testing.T) {
	a1 := Access{ID: "testmachine1", AccessType: Admin, Type: Machine}
	a2 := Access{ID: "testuser", AccessType: Write, Type: User}
	a3 := Access{ID: "testmachine", AccessType: Read, Type: MachinePrefix}
	a6 := Access{ID: "spiffe://example.com/serviceA", AccessType: Read, Type: Service}
	validACL := ACL([]Access{a1, a2, a3, a6})
	if validACL.Validate() != nil {
		t.Error("ValidACL should be valid")
	}

	a4 := Access{ID: "testmachine", AccessType: None, Type: MachinePrefix}
	noneACL := ACL([]Access{a1, a2, a4})
	if noneACL.Validate() == nil {
		t.Error("noneACL should err")
	}

	a5 := Access{ID: "testmachine1", AccessType: Write, Type: Machine}
	dupACL := ACL([]Access{a1, a5, a3})
	if dupACL.Validate() == nil {
		t.Error("dupACL should err")
	}
}

func TestACLAddMultiple(t *testing.T) {
	a1 := Access{ID: "testmachine", AccessType: Admin, Type: Machine}
	a3 := Access{ID: "testmachine", AccessType: None, Type: Machine}
	a4 := Access{ID: "testmachine2", AccessType: Admin, Type: Machine}
	acl := ACL([]Access{a1})
	acl2 := acl.Add(a4)
	if len(acl2) != 2 {
		t.Error("Unexpected ACL for adding access")
	}
	acl3 := acl2.Add(a3)
	if len(acl3) != 1 {
		t.Error("Unexpected ACL length")
	}
	if acl3[0].ID != a4.ID {
		t.Error("Removed incorrect ID")
	}
	acl4 := acl3.Add(a3)
	if len(acl4) != 1 {
		t.Error("Unexpected ACL length")
	}

}

func TestACLAdd(t *testing.T) {
	a1 := Access{ID: "testmachine", AccessType: Admin, Type: Machine}
	a2 := Access{ID: "testmachine", AccessType: Write, Type: Machine}
	a3 := Access{ID: "testmachine", AccessType: None, Type: Machine}
	a4 := Access{ID: "testmachine2", AccessType: Admin, Type: Machine}
	acl := ACL([]Access{a1})
	acl1 := acl.Add(a2)
	if len(acl1) != 1 || acl1[0].AccessType != Write {
		t.Error("Unexpected ACL for adding different access type")
	}
	acl2 := acl.Add(a3)
	if len(acl2) != 0 {
		t.Error("Unexpected ACL for removing access")
	}
	acl3 := acl.Add(a4)
	if len(acl3) != 2 {
		t.Error("Unexpected ACL for adding access")
	}

}
func TestAccessTypeCanAccess(t *testing.T) {
	if Read.CanAccess(Admin) || Read.CanAccess(Write) || !Read.CanAccess(Read) || !Read.CanAccess(None) {
		t.Error("Read has incorrect access")
	}
	if Write.CanAccess(Admin) || !Write.CanAccess(Write) || !Write.CanAccess(Read) || !Write.CanAccess(None) {
		t.Error("Write has incorrect access")
	}
	if !Admin.CanAccess(Admin) || !Admin.CanAccess(Write) || !Admin.CanAccess(Read) || !Admin.CanAccess(None) {
		t.Error("Admin has incorrect access")
	}
	if None.CanAccess(Admin) || None.CanAccess(Write) || None.CanAccess(Read) || !None.CanAccess(None) {
		t.Error("None has incorrect access")
	}
}

func TestKeyValidate(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Inactive, 10}
	v4 := KeyVersion{3, d, Active, 10}
	validKVL := KeyVersionList([]KeyVersion{v1, v2, v3})
	invalidKVL := KeyVersionList([]KeyVersion{v1, v2, v3, v4})

	a1 := Access{ID: "testmachine1", AccessType: Admin, Type: Machine}
	a2 := Access{ID: "testuser", AccessType: Write, Type: User}
	a3 := Access{ID: "testmachine", AccessType: Read, Type: MachinePrefix}
	a4 := Access{ID: "testmachine", AccessType: None, Type: MachinePrefix}
	a5 := Access{ID: "spiffe://example.com/serviceA", AccessType: Admin, Type: Service}
	validACL := ACL([]Access{a1, a2, a3, a5})
	invalidACL := ACL([]Access{a1, a2, a4})

	validKeyID := "test_key"
	invalidKeyID := "testkey "

	validHash := validKVL.Hash()
	invalidHash := "INVALID_HASH"

	validKey := Key{ID: validKeyID, ACL: validACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey1 := Key{ID: invalidKeyID, ACL: validACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey2 := Key{ID: validKeyID, ACL: invalidACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey3 := Key{ID: validKeyID, ACL: validACL, VersionList: invalidKVL, VersionHash: validHash}
	invalidKey4 := Key{ID: validKeyID, ACL: validACL, VersionList: validKVL, VersionHash: invalidHash}

	if validKey.Validate() != nil {
		t.Error("Valid Key should validate successfully")
	}
	if invalidKey1.Validate() == nil {
		t.Error("Invalid Key ID should fail to validate successfully")
	}
	if invalidKey2.Validate() == nil {
		t.Error("Invalid ACL should fail to validate successfully")
	}
	if invalidKey3.Validate() == nil {
		t.Error("Invalid KVL should fail to validate successfully")
	}
	if invalidKey4.Validate() == nil {
		t.Error("Invalid Version Hash should fail to validate successfully")
	}

}

func TestKeyVersionListValidate(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Inactive, 10}
	validKVL := KeyVersionList([]KeyVersion{v1, v2, v3})
	if validKVL.Validate() != nil {
		t.Error("Valid KVL should be valid")
	}

	v4 := KeyVersion{3, d, Active, 10}
	dupKVL := KeyVersionList([]KeyVersion{v1, v2, v3, v4})
	if dupKVL.Validate() == nil {
		t.Error("Duplicate version id, KVL should be invalid.")
	}

	v5 := KeyVersion{4, d, Primary, 10}
	twoPrimaryKVL := KeyVersionList([]KeyVersion{v1, v2, v3, v5})
	if twoPrimaryKVL.Validate() == nil {
		t.Error("KVL with two primary versions should be invalid.")
	}
}

func TestKVLGetActive(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Inactive, 10}
	kvl := KeyVersionList([]KeyVersion{v1, v2, v3})
	keys := kvl.GetActive()
	if len(keys) != 2 {
		t.Error("Invalid number of keys returned from GetActive")
	}
	for _, k := range keys {
		switch k.ID {
		case 1:
		case 2:
		case 3:
			t.Error("Received invalid key in GetActive response")
		default:
			t.Error("Unknown key version in GetActive response")
		}
	}
}

func TestKVLGetPrimary(t *testing.T) {
	d := []byte("test")
	v1 := KeyVersion{1, d, Primary, 10}
	v2 := KeyVersion{2, d, Active, 10}
	v3 := KeyVersion{3, d, Inactive, 10}
	kvl := KeyVersionList([]KeyVersion{v1, v2, v3})
	keyVersion := kvl.GetPrimary()
	if keyVersion.ID != v1.ID {
		t.Error("Incorrect version returned from getPrimary")
	}
}
