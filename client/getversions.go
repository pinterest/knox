package client

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pinterest/knox"
)

func init() {
	cmdGetVersions.Run = runGetVersions // break init cycle
}

var cmdGetVersions = &Command{
	UsageLine: "versions [-s state] [-v] <key_identifier>",
	Short:     "gets the versions for a key",
	Long: `
versions get all of the version ids for a key.

-s specifies the minimum state of key to return. By default this is set to active which means active and primary keys are returned. Accepted values include inactive, active, and primary.
-v enables verbose output, which shows the state of each version alongside the version number.

This requires read access to the key and can use user or machine authentication.

For more about knox, see https://github.com/pinterest/knox.

See also: knox keys, knox get
	`,
}
var getVersionsState = cmdGetVersions.Flag.String("s", "active", "")
var verboseOutput = cmdGetVersions.Flag.Bool("v", false, "verbose")

func runGetVersions(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("get takes only one argument. See 'knox help versions'"), false}
	}

	var status knox.VersionStatus
	switch strings.ToLower(*getVersionsState) {
	case "active":
		status = knox.Active
	case "primary":
		status = knox.Primary
	case "inactive":
		status = knox.Inactive
	}

	keyID := args[0]
	keyAccess, err := cli.GetKeyWithStatus(keyID, status)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error getting key: %s", err.Error()), true}
	}
	kvl := keyAccess.Key.VersionList
	for _, v := range kvl {
		status, err := json.Marshal(v.Status)
		if err != nil {
			status = []byte("(unknown)")
		}
		if *verboseOutput {
			fmt.Printf("%d %s\n", v.ID, string(status))
		} else {
			fmt.Printf("%d\n", v.ID)
		}
	}
	return nil
}
