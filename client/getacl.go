package client

import (
	"fmt"
	"encoding/json"
)

func init() {
	cmdGetACL.Run = runGetACL // break init cycle
}

var cmdGetACL = &Command{
	UsageLine: "acl <key_identifier>",
	Short:     "gets the ACL for a key",
	Long: `
Acl get the ACL for a key.

This doesn't require any access to the key and allows, e.g., to see who has admin access to ask for grants.

For more about knox, see https://github.com/pinterest/knox.

See also: knox keys, knox get
	`,
}

func runGetACL(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("acl takes only one argument. See 'knox help acl'")
	}

	keyID := args[0]
	acl, err := cli.GetACL(keyID)
	if err != nil {
		fatalf("Error getting key ACL: %s", err.Error())
	}

	for _, a := range *acl {
		aEnc, _ := json.Marshal(a)
		fmt.Println(string(aEnc))		
	}
}
