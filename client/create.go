package client

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pinterest/knox"
)

func init() {
	cmdCreate.Run = runCreate // break init cycle
}

var cmdCreate = &Command{
	UsageLine: "create [--key-template template_name] <key_identifier>",
	Short:     "creates a new key",
	Long: `
Create will create a new key in knox with original data set as the primary data. There are two ways to provide data in order to create a new key.

First way: key data is sent to stdin.
Please use command "create <key_identifier>". 

Second way: using supported tink key template to create a new tink keyset containing a single key, which will be used as the data directly.
Please use command "create --key-template template_name <key_identifier>".
To check supported tink key templates, please use command "key-templates".

The original key version id will be print to stdout.

To create a new key, user credentials are required. The default access list will include the creator of this key and a limited set of site reliablity and security engineers.

For more about knox, see https://github.com/pinterest/knox.

See also: knox add, knox get
	`,
}
var createTinkKeyset = cmdCreate.Flag.String("key-template", "", "")

func runCreate(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("create takes exactly one argument. See 'knox help create'")
	}
	keyID := args[0]
	var data []byte
	var err error
	if *createTinkKeyset != "" {
		templateName := *createTinkKeyset
		err = checkTemplateNameAndKnoxIDForTinkKeyset(templateName, keyID)
		if err != nil {
			fatalf(err.Error())
		}
		data = createNewTinkKeyset(tinkKeyTemplates[templateName].templateFunc)
	} else {
		data, err = readDataFromStdin()
		if err != nil {
			fatalf("Problem reading key data: %s", err.Error())
		}
	}
	// TODO(devinlundberg): allow ACL to be entered as input
	acl := knox.ACL{}
	versionID, err := cli.CreateKey(keyID, data, acl)
	if err != nil {
		fatalf("Error adding version: %s", err.Error())
	}
	fmt.Printf("Created key with initial version %d\n", versionID)
}

func readDataFromStdin() ([]byte, error) {
	fmt.Println("Reading from stdin...")
	data, err := ioutil.ReadAll(os.Stdin)
	return data, err
}
