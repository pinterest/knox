package client

import (
	"fmt"
)

var cmdGetKeys = &Command{
	Run:       runGetKeys,
	UsageLine: "keys [<version_id> ...]",
	Short:     "gets keys and associated version hash",
	Long: `
Get Keys takes version ids returns matching key ids if they exist.

If no version ids are given, it returns all key ids.

This requires valid user or machine authentication, but there are no authorization requirements.

For more about knox, see https://github.com/pinterest/knox.

See also: knox get, knox create, knox daemon
	`,
}

func runGetKeys(cmd *Command, args []string) *ErrorStatus {
	m := map[string]string{}
	for _, s := range args {
		m[s] = "NONE"
	}
	l, err := cli.GetKeys(m)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error getting keys: %s", err.Error()), true}
	}
	for _, k := range l {
		fmt.Println(k)
	}
	return nil
}
