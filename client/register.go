package client

import (
	"encoding/json"
	"fmt"
	"github.com/pinterest/knox"
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
-g gets the key as well (in no-cache mode, only -g with -k is supported)

For a machine to access a certain key, it needs permissions on that key.

Note that knox register will only update the register file and will return successful
even if the machine does not have access to the key. The daemon will actually retrieve
the key.

In no-cache mode (when using UncachedHTTPClient), only the -g flag with -k is supported
to fetch a key directly from the server without local registration.

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
	// Validate -g flag usage early: -g requires -k (cannot be used with -f alone)
	if *registerAndGet && *registerKey == "" {
		return &ErrorStatus{fmt.Errorf("the -g flag requires -k to specify a single key to retrieve"), false}
	}

	_, isUncachedMode := cli.(*knox.UncachedHTTPClient)

	// In uncached mode, only support -g with -k to fetch a key directly from the server
	if isUncachedMode {
		if !*registerAndGet {
			return &ErrorStatus{fmt.Errorf("cannot register keys in no-cache mode; use -g with -k to fetch a key directly"), false}
		}
		// -k is already validated above
		// Skip registration, go directly to fetching the key
		return fetchAndPrintKey(*registerKey, *registerTimeout)
	}

	k := NewKeysFile(path.Join(daemonFolder, daemonToRegister))
	// Handle `knox register -r` (without -k or -f) to remove all registered keys
	if *registerRemove && *registerKey == "" && *registerKeyFile == "" {
		err := k.Lock()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("error obtaining file lock: %w", err), false}
		}
		err = k.Overwrite([]string{})
		if err != nil {
			k.Unlock()
			return &ErrorStatus{fmt.Errorf("failed to unregister all keys: %w", err), false}
		}
		err = k.Unlock()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("error unlocking register file: %w", err), false}
		}
		logf("Successfully unregistered all keys.")
		return nil
	} else if *registerKey == "" && *registerKeyFile == "" {
		return &ErrorStatus{fmt.Errorf("you must include a key or key file to register; see 'knox help register'"), false}
	}
	// Get the list of keys to add
	var ks []string
	var err error
	if *registerKey == "" {
		f := NewKeysFile(*registerKeyFile)
		ks, err = f.Get()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("error reading input key file: %w", err), false}
		}
	} else {
		ks = []string{*registerKey}
	}
	// Handle adding new keys to the registered file
	// When -r is specified with -k or -f, this replaces all registered keys with the specified ones
	err = k.Lock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error obtaining file lock: %w", err), false}
	}
	if *registerRemove {
		logf("Attempting to overwrite existing keys with %v.", ks)
		err = k.Overwrite(ks)
	} else {
		err = k.Add(ks)
	}
	if err != nil {
		k.Unlock()
		return &ErrorStatus{fmt.Errorf("error registering keys %v: %w", ks, err), false}
	}
	err = k.Unlock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error unlocking register file: %w", err), false}
	}
	// If specified, force retrieval of keys (already validated that -k is set when -g is used)
	if *registerAndGet {
		return fetchAndPrintKey(*registerKey, *registerTimeout)
	}
	logf("Successfully registered keys %v. Keys are updated by the daemon process every %.0f minutes. Check the log for the most recent run.", ks, daemonRefreshTime.Minutes())
	return nil
}

// fetchAndPrintKey fetches a key from the server and prints it as JSON.
// This is used by both cached and uncached modes when -g flag is specified.
//
// Note: The timeout bounds the total retry time, but individual CacheGetKey calls
// may block beyond the deadline since CacheGetKey doesn't support context cancellation.
// The deadline is checked before each retry attempt to minimize overage.
func fetchAndPrintKey(keyID string, timeoutStr string) *ErrorStatus {
	timeout, err := parseTimeout(timeoutStr)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("invalid value for timeout flag: %w", err), false}
	}

	// Start deadline timer before first call to bound total time
	deadline := time.After(timeout)
	var key *knox.Key
	var fetchErr error // Track fetch errors separately for clarity

	for {
		// Check timeout before each attempt
		select {
		case <-deadline:
			if fetchErr != nil {
				return &ErrorStatus{fmt.Errorf(
					"error getting key from server (hit timeout after %s): %w",
					timeout.String(), fetchErr), false}
			}
			// Timeout on first attempt before any fetch was made
			return &ErrorStatus{fmt.Errorf(
				"error getting key from server (hit timeout after %s before fetch attempt)",
				timeout.String()), false}
		default:
			// Continue with fetch attempt
		}

		key, fetchErr = cli.CacheGetKey(keyID)
		if fetchErr == nil {
			break
		}

		// Wait before retry, but also check deadline
		select {
		case <-deadline:
			return &ErrorStatus{fmt.Errorf(
				"error getting key from server (hit timeout after %s): %w",
				timeout.String(), fetchErr), false}
		case <-time.After(registerRecheckTime):
			// Continue to next attempt
		}
	}

	data, marshalErr := json.Marshal(key)
	if marshalErr != nil {
		return &ErrorStatus{marshalErr, true}
	}
	fmt.Printf("%s", string(data))
	return nil
}
