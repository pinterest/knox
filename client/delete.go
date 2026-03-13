package client

import (
	"fmt"
)

var cmdDelete = &Command{
	Run:       runDelete,
	UsageLine: "delete <key_identifier>",
	Short:     "deletes an existing key",
	Long: `
This will delete your key and all data from the knox server. This operation is dangerous and requires admin permissions

For more about knox, see https://github.com/pinterest/knox.

See also: knox create
    `,
}

func runDelete(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("delete takes exactly one argument; see 'knox help delete'"), false}
	}

	err := cli.DeleteKey(args[0])
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error deleting key: %w", err), true}
	}
	fmt.Printf("Successfully deleted key\n")
	return nil
}
