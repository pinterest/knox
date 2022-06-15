package client

import (
	"fmt"

	"github.com/pinterest/knox"
)

var cmdDeactivate = &Command{
	Run:       runDeactivate,
	UsageLine: "deactivate <key_identifier> <key_version>",
	Short:     "deactivates a key version",
	Long: `
Deactivate takes an active key version and makes it inactive.

Inactive keys should not be used at all for any operation.

Primary keys cannot be deactivated. Only active keys can be deactivated.

This command requires write access to the key.

For more about knox, see https://github.com/pinterest/knox.

See also: knox reactivate, knox promote
	`,
}

func runDeactivate(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 2 {
		return &ErrorStatus{fmt.Errorf("deactivate takes exactly two argument. See 'knox help deactivate'"), false}
	}
	keyID := args[0]
	keyVersion := args[1]

	err := cli.UpdateVersion(keyID, keyVersion, knox.Inactive)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error updating version: %s", err.Error()), true}
	}
	fmt.Printf("Deactivated %s successfully.\n", keyVersion)
	return nil
}
