package client

import (
	"fmt"

	"github.com/pinterest/knox"
)

func init() {
	cmdAdd.Run = runAdd // break init cycle
}

var cmdAdd = &Command{
	UsageLine: "add [--key-template template_name] <key_identifier>",
	Short:     "adds a new key version to knox",
	Long: `
add will add a new key version to an existing key in knox. There are two ways to provide data in order to add a new key version.

First way: key data is sent to stdin.
Please use command "add <key_identifier>". 

Second way: using supported tink key template to create a new tink keyset containing a single key, which will be used as the data for the new version directly.
Please use command "add --key-template template_name <key_identifier>".
To check supported tink key templates, please use command "key-templates".

This key version will be set to active upon creation. The version id will be sent to stdout on creation.

This command uses user access and requires write access in the key's ACL.

For more about knox, see https://github.com/pinterest/knox.

See also: knox create, knox promote
	`,
}
var addTinkKeyset = cmdAdd.Flag.Bool("key-template", false, "")

func runAdd(cmd *Command, args []string) {
	if len(args) != 1 && len(args) != 2 || len(args) == 2 && !*addTinkKeyset || 
	len(args) != 2 && *addTinkKeyset {
		fatalf("unsupported command. See 'knox help add'")
	}
	var keyID string
	var data []byte
	if *addTinkKeyset {
		templateName := args[0]
		keyID = args[1]
		if err := checkTemplateNameAndKnoxIDForTinkKeyset(templateName, keyID); err != nil {
			fatalf(err.Error())
		}
		// get all versions (primary, active, inactive) of this knox identifier
		allExistedVersions, err := cli.NetworkGetKeyWithStatus(keyID, knox.Inactive)
		if err != nil {
			fatalf("Error getting key: %s", err.Error())
		}
		data = addNewTinkKeyset(tinkKeyTemplates[templateName].templateFunc, allExistedVersions.VersionList)
	} else {
		keyID = args[0]
		data = readDataFromStdin()
	}
	versionID, err := cli.AddVersion(keyID, data)
	if err != nil {
		fatalf("Error adding version: %s", err.Error())
	}
	fmt.Printf("Added key version %d\n", versionID)
}
