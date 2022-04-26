package client

import (
	"fmt"
)

var cmdUnregister = &Command{
	Run:       runUnregister,
	UsageLine: "unregister <key_identifier>",
	Short:     "unregister a key identifier from daemon",
	Long: `
Unregister stops cacheing and refreshing a specific key, deleting the associated files.

For more about knox, see https://github.com/pinterest/knox.

See also: knox register, knox daemon
	`,
}

func runUnregister(cmd *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{fmt.Errorf("You must include a key ID to deregister. See 'knox help unregister'"), false}
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)
	err := k.Lock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error locking the register file: %s", err.Error()), false}
	}
	defer k.Unlock()

	err = k.Remove([]string{args[0]})
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error removing the key: %s", err.Error()), false}
	}
	fmt.Println("Unregistered key successfully")
	return nil
}
