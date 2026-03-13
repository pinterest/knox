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
		return &ErrorStatus{fmt.Errorf("you must include a key ID to deregister; see 'knox help unregister'"), false}
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)
	err := k.Lock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error locking the register file: %w", err), false}
	}
	defer k.Unlock()

	err = k.Remove([]string{args[0]})
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error removing the key: %w", err), false}
	}
	fmt.Println("Unregistered key successfully")
	return nil
}
