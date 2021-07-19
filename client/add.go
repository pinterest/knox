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
Add will add a new key version to an existing key in knox. Key data of new version should be sent to stdin unless a key-template is specified.

First way: key data of new version is sent to stdin.
Please run "knox add <key_identifier>". 

Second way: the key-template option can be used to specify a template to generate the new key version, instead of stdin. For available key templates, run "knox key-templates".
Please run "knox add --key-template <template_name> <key_identifier>".

This key version will be set to active upon creation. The version id will be sent to stdout on creation.

This command uses user access and requires write access in the key's ACL.

For more about knox, see https://github.com/pinterest/knox.

See also: knox create, knox promote
	`,
}
var addTinkKeyset = cmdAdd.Flag.String("key-template", "", "name of a knox-supported Tink key template")

func runAdd(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("add takes only one argument. See 'knox help add'")
	}
	keyID := args[0]
	var data []byte
	var err error
	if *addTinkKeyset != "" {
		data, err = getDataWithTemplate(*addTinkKeyset, keyID)
	} else {
		data, err = readDataFromStdin()
	}
	if err != nil {
		fatalf(err.Error())
	}
	versionID, err := cli.AddVersion(keyID, data)
	if err != nil {
		fatalf("Error adding version: %s", err.Error())
	}
	fmt.Printf("Added key version %d\n", versionID)
}

// getDataWithTemplate returns the data for a new version of a knox identifier that stores Tink keyset.
func getDataWithTemplate(templateName string, keyID string) ([]byte, error) {
	err := obeyNamingRule(templateName, keyID)
	if err != nil {
		return nil, err
	}
	// get all versions (primary, active, inactive) of this knox identifier
	allVersions, err := cli.NetworkGetKeyWithStatus(keyID, knox.Inactive)
	if err != nil {
		return nil, fmt.Errorf("error getting key: %s", err.Error())
	}
	return addNewTinkKeyset(tinkKeyTemplates[templateName].templateFunc, allVersions.VersionList)
}
