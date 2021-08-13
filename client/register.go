package client

import (
	"encoding/json"
	"fmt"
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

-r removes all existing registered keys.
-k specifies a specific key identifier to register
-f specifies a file containing a new line separated list of key identifiers
-t specifies a timeout for getting the key from the daemon in seconds
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
var registerTimeout = cmdRegister.Flag.Int("t", 5, "")

const registerRecheckTime = 10 * time.Millisecond

func runRegister(cmd *Command, args []string) {
	if *registerKey == "" && *registerKeyFile == "" {
		fatalf("You must include a key or key file to register. see 'knox help register'")
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)

	var err error
	var cmdName string
	var ks []string
	if *registerKey == "" {
		f := NewKeysFile(*registerKeyFile)
		ks, err = f.Get()
		if err != nil {
			fatalf("There was an error reading input key file %s", err.Error())
		}
	} else {
		ks = []string{*registerKey}
	}

	err = k.Lock()
	if err != nil {
		fatalf("There was an error obtaining file lock: %s", err.Error())
	}
	if *registerRemove {
		cmdName = "unregister"
		err = k.Overwrite(ks)
	} else {
		cmdName = "register"
		err = k.Add(ks)
	}

	if err != nil {
		k.Unlock()
		fatalf("There was an error %ving keys %v: %s", cmdName, ks, err.Error())
	}
	err = k.Unlock()
	if err != nil {
		errorf("There was an error unlocking register file: %s", err.Error())
	}
	if *registerAndGet {
		key, err := cli.CacheGetKey(*registerKey)
		c := time.After(time.Duration(*registerTimeout) * time.Second)
		for err != nil {
			select {
			case <-c:
				fatalf(
					"Error getting key from daemon (hit timeout after %d seconds); check knox logs for details (most recent error: %v)",
					*registerTimeout, err)
			case <-time.After(registerRecheckTime):
				key, err = cli.CacheGetKey(*registerKey)
			}
		}
		// TODO: add json vs data option?
		data, err := json.Marshal(key)
		if err != nil {
			fatalf(err.Error())
		}
		fmt.Printf("%s", string(data))
		return
	}
	logf("Successfully %ved keys %v. Keys are updated by the daemon process every %.0f minutes. Check the log for the most recent run.", cmdName, ks, daemonRefreshTime.Minutes())
}
