package client

import (
	"fmt"
	"io"
	"os"

	"github.com/pinterest/knox"
)

func init() {
	cmdCreate.Run = runCreate // break init cycle
}

var cmdCreate = &Command{
	UsageLine: "create [--key-template template_name] [-acl acl_file] <key_identifier>",
	Short:     "creates a new key",
	Long: `
Create will create a new key in knox with input as the primary key version. Key data should be sent to stdin unless a key-template is specified.

First way: key data is sent to stdin.
Please run "knox create <key_identifier>". 

Second way: the key-template option can be used to specify a template to generate the initial primary key version, instead of stdin. For available key templates, run "knox key-templates".
Please run "knox create --key-template <template_name> <key_identifier>".

-acl: Takes in a filename with a JSON formatted list of access rules to set on the key at creation time, in the same format as "knox access -acl".

The original key version id will be print to stdout.

To create a new key, user credentials are required. The default access list will include the creator of this key and a limited set of site reliablity and security engineers.

For more about knox, see https://github.com/pinterest/knox.

See also: knox add, knox get
	`,
}
var createTinkKeyset = cmdCreate.Flag.String("key-template", "", "name of a knox-supported Tink key template")
var createACL = cmdCreate.Flag.String("acl", "", "file containing a JSON formatted list of access rules")

func runCreate(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("create takes exactly one argument; see 'knox help create'"), false}
	}
	keyID := args[0]
	var err error
	// Parse the ACL file (if any) before reading key data so that an
	// unreadable or malformed file fails fast, without first consuming the
	// user's secret from stdin.
	acl := knox.ACL{}
	if *createACL != "" {
		acl, err = parseACLFile(*createACL)
		if err != nil {
			return &ErrorStatus{err, false}
		}
	}
	var data []byte
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
	versionID, err := cli.CreateKey(keyID, data, acl)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error adding version: %w", err), true}
	}
	fmt.Printf("Created key with initial version %d\n", versionID)
	return nil
}

func readDataFromStdin() ([]byte, error) {
	fmt.Println("Reading from stdin...")
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return data, fmt.Errorf("problem reading key data: %w", err)
	}
	return data, nil
}
