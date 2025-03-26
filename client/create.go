package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pinterest/knox"
)

func init() {
	cmdCreate.Run = runCreate // break init cycle
}

var cmdCreate = &Command{
	UsageLine: "create [--acl key_acl] [--key-template template_name] <key_identifier>",
	Short:     "creates a new key",
	Long: `
Create will create a new key in knox with input as the primary key version. Key data should be sent to stdin unless a key-template is specified.

First way: key data is sent to stdin.
Please run "knox create <key_identifier>". 

Second way: the key-template option can be used to specify a template to generate the initial primary key version, instead of stdin. For available key templates, run "knox key-templates".
Please run "knox create --key-template <template_name> <key_identifier>".

The original key version id will be print to stdout.

Only users or SPIFFEs can create a new key. For SPIFFEs, an ACL must be provided with at least 2 users/groups set as admins.
The default ACL will include a limited set of site reliablity and security engineers, and the creator if they are a user.

For more about knox, see https://github.com/pinterest/knox.

See also: knox add, knox get
	`,
}
var createTinkKeyset = cmdCreate.Flag.String("key-template", "", "name of a knox-supported Tink key template")
var createAcl = cmdCreate.Flag.String("acl", "", "ACL for the created key")

func parseAcl(aclString string) (knox.ACL, error) {
	var err error
	var accessList []knox.Access

	if aclString == "" {
		return knox.ACL{}, nil
	}

	err = json.Unmarshal([]byte(aclString), &accessList)
	if err != nil {
		return nil, err
	}

	acl := knox.ACL(accessList)

	err = acl.Validate()
	if err != nil {
		return nil, err
	}
	err = acl.ValidateHasMultipleHumanAdmins()
	if err != nil {
		return nil, err
	}

	return acl, nil
}

func runCreate(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("create takes exactly one argument. See 'knox help create'"), false}
	}
	keyID := args[0]
	var data []byte
	var err error
	if *createTinkKeyset != "" {
		templateName := *createTinkKeyset
		err = obeyNamingRule(templateName, keyID)
		if err != nil {
			return &ErrorStatus{err, false}
		}
		data, err = createNewTinkKeyset(tinkKeyTemplates[templateName].templateFunc)
	} else {
		data, err = readDataFromStdin()
	}
	if err != nil {
		return &ErrorStatus{err, false}
	}

	var acl knox.ACL
	acl, err = parseAcl(*createAcl)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error parsing ACL: %s", err.Error()), false}
	}

	versionID, err := cli.CreateKey(keyID, data, acl)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error adding version: %s", err.Error()), true}
	}
	fmt.Printf("Created key with initial version %d\n", versionID)
	return nil
}

func readDataFromStdin() ([]byte, error) {
	fmt.Println("Reading from stdin...")
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return data, fmt.Errorf("problem reading key data: %s", err.Error())
	}
	return data, nil
}
