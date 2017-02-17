package client

import (
	"fmt"

	"github.com/pinterest/knox"
)

func init() {
	cmdUpdateAccess.Run = runUpdateAccess
}

var cmdUpdateAccess = &Command{
	UsageLine: "access {-n|-r|-w|-a} {-M|-U|-G|-P} <key_identifier> <principal>",
	Short:     "access modifies the acl of a key",
	Long: `
Access will add or change the acl on a key by adding a specific access control rule.

-n: This will update the key so that the given principal has no access. Please note that if there is another rule that gives access that will take precedence.
-r: This will grant the principal read access to the key. They will be able to read the keys data.
-w: This will grant the principal write access to the key. They will be able to rotate keys in addition to all read permissions.
-a: This will grant the principal admin access to the key. They will be able to update ACLs and delete keys in addition to all read and write permissions.

-M: A specific machine. The principal should be set to the exact hostname.
-U: A specific user. The principal should be set to the ldap username of the user.
-G: A specific user group. The principal should be set to the group name. This takes the format of ou=Security,ou=Prod,ou=groups,dc=pinterest,dc=com in LDAP.
-P: A machine hostname prefix. Prefix matching will be used to determine access. For example, if the principal is set to 'auth' then 'auth004' would match (and so would any hostname beginning with auth).

This command requires admin access to the key.

For more about knox, see https://github.com/pinterest/knox.

See also: knox create, knox get
	`,
}

var updateAccessNone = cmdUpdateAccess.Flag.Bool("n", false, "")
var updateAccessRead = cmdUpdateAccess.Flag.Bool("r", false, "")
var updateAccessWrite = cmdUpdateAccess.Flag.Bool("w", false, "")
var updateAccessAdmin = cmdUpdateAccess.Flag.Bool("a", false, "")

var updateAccessMachine = cmdUpdateAccess.Flag.Bool("M", false, "")
var updateAccessUser = cmdUpdateAccess.Flag.Bool("U", false, "")
var updateAccessGroup = cmdUpdateAccess.Flag.Bool("G", false, "")
var updateAccessPrefix = cmdUpdateAccess.Flag.Bool("P", false, "")

func runUpdateAccess(cmd *Command, args []string) {
	if len(args) != 2 {
		fatalf("access takes exactly two arguments. See 'knox help access'")
	}
	keyID := args[0]
	principal := args[1]
	var access knox.Access
	access.ID = principal
	switch {
	case *updateAccessNone:
		access.AccessType = knox.None
	case *updateAccessRead:
		access.AccessType = knox.Read
	case *updateAccessWrite:
		access.AccessType = knox.Write
	case *updateAccessAdmin:
		access.AccessType = knox.Admin
	default:
		fatalf("access requires {-n,-r,-w,-a}. See 'knox help access'")
	}
	switch {
	case *updateAccessMachine:
		access.Type = knox.Machine
	case *updateAccessUser:
		access.Type = knox.User
	case *updateAccessGroup:
		access.Type = knox.UserGroup
	case *updateAccessPrefix:
		access.Type = knox.MachinePrefix
	default:
		fatalf("access requires {-M|-U|-G|-P}. See 'knox help access'")
	}
	err := cli.PutAccess(keyID, &access)
	if err != nil {
		fatalf("Failed to update access: %s", err.Error())
	}
	fmt.Println("Successfully updated Access")
}
