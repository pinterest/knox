package client

import (
	"fmt"
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

	validAclNoHumanAdmin := knox.ACL([]knox.Access{machineAdmin, userWrite})
	validAclWithHumanAdmin := knox.ACL([]knox.Access{machineAdmin, userAdmin})
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
			"ACL needs to have a user or group set as an admin", // User only has Write access
	    },
	    {
			`[{"type":"Machine","id":"testmachine1","access":"Admin"}, {"type":"User","id":"testuser","access":"Admin"}]`,
			validAclWithHumanAdmin,
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
				t.Fatal(err)
			}
		} else{
			if !testAclEq(acl, tc.acl) {
				t.Fatalf("%v should equal %v", acl, tc.acl)
			}
		}
	}
}
