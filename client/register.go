package client

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"time"
)

func init() {
	cmdRegister.Run = runRegister
}

var cmdRegister = &Command{
	UsageLine: "register [-r] [-k identifier] [-f identifier_file] [-g]",
	Short:     "register keys to cache locally using daemon",
	Long: `
Register will cache the key in the file system and keep it up to date using the file system.

-r removes all existing registered keys. -k or -f will instead replace all registered keys with those specified
-k specifies a specific key identifier to register
-f specifies a file containing a new line separated list of key identifiers
-t specifies a timeout for getting the key from the daemon (e.g. '5s', '500ms')
-g gets the key as well

For a machine to access a certain key, it needs permissions on that key.

Note that knox register will only update the register file and will return successful
even if the machine does not have access to the key. The daemon will actually retrieve
the key.

For more about knox, see https://github.com/pinterest/knox.

See also: knox unregister, knox daemon
	`,
}

var registerRemove = cmdRegister.Flag.Bool("r", false, "")
var registerKey = cmdRegister.Flag.String("k", "", "")
var registerKeyFile = cmdRegister.Flag.String("f", "", "")
var registerAndGet = cmdRegister.Flag.Bool("g", false, "")
var registerTimeout = cmdRegister.Flag.String("t", "5s", "")

const registerRecheckTime = 10 * time.Millisecond

func parseTimeout(val string) (time.Duration, error) {
	// For backwards-compatibility, a timeout value that is a simple integer will
	// be treated as a number of seconds. This ensures that the historical usage
	// of the timeout flag like '-t5' retains the same meaning.
	if secs, err := strconv.Atoi(val); err == nil {
		return time.Duration(secs) * time.Second, nil
	}

	// For all other values, use time.ParseDuration.
	return time.ParseDuration(val)
}

func runRegister(cmd *Command, args []string) *ErrorStatus {
	timeout, err := parseTimeout(*registerTimeout)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Invalid value for timeout flag: %s", err.Error()), false}
	}

	k := NewKeysFile(path.Join(daemonFolder, daemonToRegister))
	if *registerRemove && *registerKey == "" && *registerKeyFile == "" {
		// Short circuit & handle `knox register -r`, which is expected to remove all keys
		err := k.Lock()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("There was an error obtaining file lock: %s", err.Error()), false}
		}
		err = k.Overwrite([]string{})
		if err != nil {
			k.Unlock()
			return &ErrorStatus{fmt.Errorf("Failed to unregister all keys: %s", err.Error()), false}
		}
		err = k.Unlock()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("There was an error unlocking register file: %s", err.Error()), false}
		}
		logf("Successfully unregistered all keys.")
		return nil
	} else if *registerKey == "" && *registerKeyFile == "" {
		return &ErrorStatus{fmt.Errorf("You must include a key or key file to register. see 'knox help register'"), false}
	}
	// Get the list of keys to add
	var ks []string
	if *registerKey == "" {
		f := NewKeysFile(*registerKeyFile)
		ks, err = f.Get()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("There was an error reading input key file %s", err.Error()), false}
		}
	} else {
		ks = []string{*registerKey}
	}
	// Handle adding new keys to the registered file
	err = k.Lock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("There was an error obtaining file lock: %s", err.Error()), false}
	}
	if *registerRemove {
		logf("Attempting to overwrite existing keys with %v.", ks)
		err = k.Overwrite(ks)
	} else {
		err = k.Add(ks)
	}
	if err != nil {
		k.Unlock()
		return &ErrorStatus{fmt.Errorf("There was an error registering keys %v: %s", ks, err.Error()), false}
	}
	err = k.Unlock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("There was an error unlocking register file: %s", err.Error()), false}
	}
	// If specified, force retrieval of keys
	if *registerAndGet {
		key, err := cli.CacheGetKey(*registerKey)
		c := time.After(timeout)
		for err != nil {
			select {
			case <-c:
				return &ErrorStatus{fmt.Errorf(
					"Error getting key from daemon (hit timeout after %s seconds); check knox logs for details (most recent error: %v)",
					timeout.String(), err), false}
			case <-time.After(registerRecheckTime):
				key, err = cli.CacheGetKey(*registerKey)
			}
		}
		// TODO: add json vs data option?
		data, err := json.Marshal(key)
		if err != nil {
			return &ErrorStatus{err, true}
		}
		fmt.Printf("%s", string(data))
		return nil
	}
	logf("Successfully registered keys %v. Keys are updated by the daemon process every %.0f minutes. Check the log for the most recent run.", ks, daemonRefreshTime.Minutes())
	return nil
}
