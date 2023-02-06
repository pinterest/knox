package client

import (
	"testing"

	"github.com/pinterest/knox"
)

func testAclEq(a, b knox.ACL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseAcl(t *testing.T) {
	machineAdmin := knox.Access{ID: "testmachine1", AccessType: knox.Admin, Type: knox.Machine}
	userWrite := knox.Access{ID: "testuser", AccessType: knox.Write, Type: knox.User}
	userAdmin := knox.Access{ID: "testuser", AccessType: knox.Admin, Type: knox.User}
	groupAdmin := knox.Access{ID: "testgroup", AccessType: knox.Admin, Type: knox.UserGroup}

	validAclNoHumanAdmin := knox.ACL([]knox.Access{machineAdmin, userWrite})
	validAclWithOneHumanAdmin := knox.ACL([]knox.Access{machineAdmin, userAdmin})
	validAclWithTwoHumanAdmins := knox.ACL([]knox.Access{machineAdmin, userAdmin, groupAdmin})
	blankAcl := knox.ACL{}

	testCases := []struct {
		str string
		acl knox.ACL
		errMsg string
	}{
		{
			`[{"type":"foo","id":"bar","access":"test"}]`,
			validAclNoHumanAdmin,  // ACL does not matter here
			"json: Invalid AccessType to convert",
		},
		{
			`[{"type":"User","id":"testuser","access":"Write"}, {"type":"Machine","id":"testmachine1","access":"Admin"}]`,
			validAclNoHumanAdmin,
			"ACL needs to have at least 2 users/groups set as admins", // User only has Write access
		},
		{
			`[{"type":"Machine","id":"testmachine1","access":"Admin"}, {"type":"User","id":"testuser","access":"Admin"}]`,
			validAclWithOneHumanAdmin,
			"ACL needs to have at least 2 users/groups set as admins", // Only 1 human admin
		},
		{
			`[{"type":"Machine","id":"testmachine1","access":"Admin"}, {"type":"User","id":"testuser","access":"Admin"}, {"type":"UserGroup","id":"testgroup","access":"Admin"}]`,
			validAclWithTwoHumanAdmins,
			"", // Success, no error
		},
		// Original, and default, behaviour is a blank ACL
		{
			``,
			blankAcl,
			"", // Success, no error
		},
	}

	for _, tc := range testCases {
		acl, err := parseAcl(tc.str)
		if tc.errMsg != "" || err != nil {
			if err.Error() != tc.errMsg {
				t.Fatalf("%v should equal %v", tc.errMsg, err.Error())
			}
		} else{
			if !testAclEq(acl, tc.acl) {
				t.Fatalf("%v should equal %v", acl, tc.acl)
			}
		}
	}
}
