package client

import (
	"encoding/json"
	"fmt"
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

func runGetACL(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("acl takes only one argument. See 'knox help acl'"), false}
	}

	keyID := args[0]
	acl, err := cli.GetACL(keyID)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error getting key ACL: %s", err.Error()), true}
	}

	for _, a := range *acl {
		aEnc, err := json.Marshal(a)
		if err != nil {
			// malformated ACL entry considered as knox server side error
			return &ErrorStatus{fmt.Errorf("Could not marshal entry: %v", a), true}
		}
		fmt.Println(string(aEnc))
	}
	return nil
}
