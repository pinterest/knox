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

-json: Returns the ACL as a JSON formatted list of access rules, useful for generating files to be used with knox access -acl.

This doesn't require any access to the key and allows, e.g., to see who has admin access to ask for grants.

For more about knox, see https://github.com/pinterest/knox.

See also: knox keys, knox get
	`,
}

var getACLJSON = cmdGetACL.Flag.Bool("json", false, "")

func runGetACL(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("acl takes only one argument. See 'knox help acl'"), false}
	}

	keyID := args[0]
	acl, err := cli.GetACL(keyID)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error getting key ACL: %s", err.Error()), true}
	}

	if *getACLJSON {
		aclEnc, err := json.Marshal(acl)
		if err != nil {
			// malformated ACL considered as knox server side error
			return &ErrorStatus{fmt.Errorf("Could not marshal ACL: %v", acl), true}
		}
		fmt.Println(string(aclEnc))
		return nil
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
