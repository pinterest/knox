package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"

	"gopkg.in/fsnotify.v1"

	"github.com/pinterest/knox"
)

var cmdDaemon = &Command{
	Run:       runDaemon,
	UsageLine: "daemon",
	Short:     "runs a process to keep keys in sync with server",
	Long: `
daemon runs the knox process that will keep keys in sync.

This process will keep running until sent a kill signal or it crashes.

This maintains a file system cache of knox keys that is used for all other knox commands.

For more about knox, see https://github.com/pinterest/knox.

See also: knox register, knox unregister
	`,
}

var daemonFolder = "/var/lib/knox"
var daemonToRegister = "/.registered"
var daemonKeys = "/v0/keys/"

var lockTimeout = 10 * time.Second
var lockRetryTime = 50 * time.Millisecond

var defaultFilePermission os.FileMode = 0666
var defaultDirPermission os.FileMode = 0777

var daemonRefreshTime = 10 * time.Minute

const tinkPrefix = "tink:"

func runDaemon(cmd *Command, args []string) *ErrorStatus {

	if os.Getenv("KNOX_MACHINE_AUTH") == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return &ErrorStatus{fmt.Errorf("you're on a host with no name: %w", err), false}
		}
		os.Setenv("KNOX_MACHINE_AUTH", hostname)
	}

	d := daemon{
		dir:          daemonFolder,
		registerFile: daemonToRegister,
		keysDir:      daemonKeys,
		cli:          cli,
	}
	err := d.initialize()
	if err != nil {
		return &ErrorStatus{err, false}
	}
	d.loop(daemonRefreshTime)
	return nil
}

type daemon struct {
	dir             string
	registerFile    string
	registerKeyFile Keys
	keysDir         string
	cli             knox.APIClient
	updateErrCount  uint64
	getKeyErrCount  uint64
	successCount    uint64
}

func (d *daemon) loop(refresh time.Duration) {
	t := time.NewTicker(refresh)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fatalf("unable to watch files: %v", err)
	}
	watcher.Add(d.registerFilename())

	for {
		logf("Daemon updating all registered keys")
		start := time.Now()
		err := d.update()
		if err != nil {
			d.updateErrCount++
			logf("failed to update keys: %v", err)
		} else {
			d.successCount++
		}
		logf("Update of keys completed after %d ms", time.Since(start).Milliseconds())

		select {
		case event := <-watcher.Events:
			// On any change to register file
			logf("Got file watcher event: %s on %s", event.Op.String(), event.Name)
		case <-t.C:
			// add random jitter to prevent a stampede
			<-time.After(time.Duration(rand.Intn(10)) * time.Millisecond)
			daemonReportMetrics(map[string]uint64{
				"err":     d.updateErrCount,
				"get_err": d.getKeyErrCount,
				"success": d.successCount,
			})
		}
	}
}

// chmodIfNeeded sets mode on path only if it differs from the current mode.
// This avoids "operation not permitted" when running as non-root when permissions are already correct.
func chmodIfNeeded(path string, want os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() == want.Perm() {
		return nil
	}
	return os.Chmod(path, want)
}

// ensureDirExists creates path as a directory with perm, or returns nil if it already exists.
// When running as non-root (e.g. in Kubernetes), the directory may have been created by an
// init container; if MkdirAll fails with permission denied, we still succeed when the path exists.
func ensureDirExists(path string, perm os.FileMode) error {
	err := os.MkdirAll(path, perm)
	if err == nil {
		return nil
	}
	info, statErr := os.Stat(path)
	if statErr == nil && info.IsDir() {
		return nil
	}
	return err
}

func (d *daemon) initialize() error {
	if err := ensureDirExists(d.dir, defaultDirPermission); err != nil {
		return fmt.Errorf("failed to initialize /var/lib/knox (run 'sudo mkdir /var/lib/knox'?): %w", err)
	}

	// Need to chmod due to a umask set on masterless puppet machines (skip if already correct for non-root)
	if err := chmodIfNeeded(d.dir, defaultDirPermission); err != nil {
		return fmt.Errorf("failed to open up directory permissions: %w", err)
	}
	if err := ensureDirExists(d.keyDir(), defaultDirPermission); err != nil {
		return fmt.Errorf("failed to make key folders: %w", err)
	}

	if err := chmodIfNeeded(d.keyDir(), defaultDirPermission); err != nil {
		return fmt.Errorf("failed to open up directory permissions: %w", err)
	}
	_, err := os.Stat(d.registerFilename())
	if os.IsNotExist(err) {
		if err := os.WriteFile(d.registerFilename(), []byte{}, defaultFilePermission); err != nil {
			return fmt.Errorf("failed to initialize registered key file: %w", err)
		}
	} else if err != nil {
		return err
	}

	if err := chmodIfNeeded(d.registerFilename(), defaultFilePermission); err != nil {
		return fmt.Errorf("failed to open up register file permissions: %w", err)
	}
	d.registerKeyFile = NewKeysFile(d.registerFilename())
	return nil
}

func (d *daemon) update() error {
	err := d.registerKeyFile.Lock()
	if err != nil {
		return err
	}
	// defer this so that functions can update the register file.
	defer d.registerKeyFile.Unlock()
	keyIDs, err := d.registerKeyFile.Get()
	if err != nil {
		return err
	}
	logf("Requested keys: %s", keyIDs)

	keyMap := map[string]string{}
	existingKeys := map[string]bool{}
	for _, k := range keyIDs {
		// set default value to empty string
		keyMap[k] = ""
		existingKeys[k] = false
	}

	currentKeyIDs, err := d.currentRegisteredKeys()
	if err != nil {
		return err
	}
	logf("Current keys on disk: %s", currentKeyIDs)

	for _, keyID := range currentKeyIDs {
		existingKeys[keyID] = true

		if _, present := keyMap[keyID]; present {
			key, err := d.cli.CacheGetKey(keyID)
			if err != nil {
				// Keep going in spite of failure
				logf("error getting cache key: %v", err)
				// Remove existing cached key with invalid format (saved with previous version clients)
				if _, err = os.Stat(d.keyFilename(keyID)); err == nil {
					d.deleteKey(keyID)
				}
			} else {
				keyMap[keyID] = key.VersionHash
			}
		} else {
			d.deleteKey(keyID)
		}
	}

	if len(keyMap) > 0 {
		updatedKeys, err := d.cli.GetKeys(keyMap)
		if err != nil {
			return err
		}
		logf("Updated keys received from server: %s", updatedKeys)
		for _, k := range updatedKeys {
			err = d.processKey(k)
			existingKeys[k] = true

			if err != nil {
				// Keep going in spite of failure
				d.getKeyErrCount++
				logf("error processing key: %v", err)
			}
		}
	}
	// Find out if we missed anything (useful for humans reading the logs)
	// If key was not processed, and is also not current, then it didn't exist
	notFound := []string{}
	for id, exists := range existingKeys {
		if !exists {
			notFound = append(notFound, id)
		}
	}
	logf("Keys not found on server: %s", notFound)

	return nil
}

func (d daemon) deleteKey(keyID string) error {
	return os.Remove(d.keyFilename(keyID))
}

func (d daemon) currentRegisteredKeys() ([]string, error) {
	files, err := os.ReadDir(d.keyDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		out = append(out, f.Name())
	}
	return out, nil
}

func (d daemon) keyDir() string {
	return path.Join(d.dir, d.keysDir)
}

func (d daemon) registerFilename() string {
	return path.Join(d.dir, d.registerFile)
}

func (d daemon) keyFilename(id string) string {
	return path.Join(d.dir, d.keysDir, id)
}

func (d daemon) processKey(keyID string) error {
	key, err := d.cli.NetworkGetKey(keyID)
	if err != nil {
		errMsg := err.Error()
		// Check for authorization or key not found errors (using contains for more robust matching)
		if strings.Contains(errMsg, "User or machine not authorized") || strings.Contains(errMsg, "Key identifier does not exist") {
			// This removes keys that do not exist or the machine is unauthorized to access
			d.registerKeyFile.Remove([]string{keyID})
		}
		return fmt.Errorf("error getting key %s: %w", keyID, err)
	}
	// Do not cache any new keys if they have invalid content
	if key.ID == "" || key.ACL == nil || key.VersionList == nil || key.VersionHash == "" {
		return fmt.Errorf("invalid key content returned")
	}

	if strings.HasPrefix(keyID, tinkPrefix) {
		keysetHandle, _, err := getTinkKeysetHandleFromKnoxVersionList(key.VersionList)
		if err != nil {
			return fmt.Errorf("error fetching keyset handle for this tink key %s: %w", keyID, err)
		}
		tinkKeyset, err := convertTinkKeysetHandleToBytes(keysetHandle)
		if err != nil {
			return fmt.Errorf("error converting tink keyset handle to bytes %s: %w", keyID, err)
		}
		key.TinkKeyset = base64.StdEncoding.EncodeToString(tinkKeyset)
	}

	b, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("error marshalling key %s: %w", keyID, err)
	}
	// Write to tmpfile, mv to normal location. Close + rm on failures
	tmpFile, err := os.CreateTemp(d.dir, fmt.Sprintf(".*.%s.tmp", keyID))
	if err != nil {
		return fmt.Errorf("error opening tmp file for key %s: %w", keyID, err)
	}
	_, err = tmpFile.Write(b)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return fmt.Errorf("error writing key %s to file: %w", keyID, err)
	}
	// Done writing
	tmpFile.Close()

	err = os.Rename(tmpFile.Name(), d.keyFilename(keyID))
	if err != nil {
		os.Remove(tmpFile.Name())
		return fmt.Errorf("error renaming key %s temporary file: %w", keyID, err)
	}

	if err := chmodIfNeeded(d.keyFilename(keyID), defaultFilePermission); err != nil {
		return fmt.Errorf("failed to open up key file permissions: %w", err)
	}
	return nil
}

// Keys are an interface for storing a list of key ids (for use with the register file to provide locks)
type Keys interface {
	Get() ([]string, error)
	Add([]string) error
	Overwrite([]string) error
	Remove([]string) error
	Lock() error
	Unlock() error
}

// KeysFile is an implementation of Keys based on the file system for the register file.
type KeysFile struct {
	fn string
	*flock
}

// NewKeysFile takes in a filename and outputs an implementation of the Keys interface
func NewKeysFile(fn string) Keys {
	return &KeysFile{fn, newFlock()}
}

// Lock performs the nonblocking syscall lock and retries until the global timeout is met.
func (k *KeysFile) Lock() error {
	err := k.lock(k, defaultFilePermission, true, lockTimeout)

	// Timeout means someone else is using our lock, which is unusual.
	// Let's collect some extra debugging information to find out why.
	if err == ErrTimeout && runtime.GOOS == "linux" {
		lockHolders, err := identifyLockHolders(k.fn)
		if err != nil {
			logf("hit timeout, found lock holder information:\n%s", lockHolders)
		}
	}

	// Annotate error with path to file to make debugging easier
	if err != nil {
		return fmt.Errorf("unable to obtain lock on file '%s': %w", k.fn, err)
	}
	return nil
}

// Unlock performs the nonblocking syscall unlock and retries until the global timeout is met.
func (k *KeysFile) Unlock() error {
	err := k.unlock(k)

	// Annotate error with path to file to make debugging easier
	if err != nil {
		return fmt.Errorf("unable to release lock on file '%s': %w", k.fn, err)
	}
	return nil
}

// Get will get the list of key ids. It expects Lock to have been called.
func (k *KeysFile) Get() ([]string, error) {
	b, err := os.ReadFile(k.fn)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(b)), nil
}

// Remove will remove the input key ids from the list. It expects Lock to have been called.
func (k *KeysFile) Remove(ks []string) error {
	oldKeys, err := k.Get()
	if err != nil {
		if os.IsNotExist(err) {
			oldKeys = []string{}
		} else {
			return err
		}
	}
	// Use a map to remove any duplicates
	newKeys := make(map[string]bool)
	for _, oldK := range oldKeys {
		removeIt := false
		for _, k := range ks {
			if k == oldK {
				removeIt = true
				break
			}
		}
		if !removeIt {
			newKeys[oldK] = true
		}
	}

	var buffer bytes.Buffer
	for k := range newKeys {
		buffer.WriteString(k)
		buffer.WriteByte('\n')
	}
	return os.WriteFile(k.fn, buffer.Bytes(), 0666)
}

// Add will add the key IDs to the list. It expects Lock to have been called.
func (k *KeysFile) Add(ks []string) error {
	oldKeys, err := k.Get()
	if err != nil {
		if os.IsNotExist(err) {
			oldKeys = []string{}
		} else {
			return err
		}
	}
	// Use a map to remove any duplicates
	newKeys := make(map[string]bool)
	for _, k := range oldKeys {
		newKeys[k] = true
	}
	for _, k := range ks {
		newKeys[k] = true
	}
	if len(newKeys) == len(oldKeys) {
		// Do not write if there are no changes
		return nil
	}

	var buffer bytes.Buffer
	for k := range newKeys {
		buffer.WriteString(k)
		buffer.WriteByte('\n')
	}
	return os.WriteFile(k.fn, buffer.Bytes(), 0666)
}

// Overwrite deletes all existing values in the key list and writes the input.
// It expects Lock to have been called.
func (k *KeysFile) Overwrite(ks []string) error {
	// Use a map to remove any duplicates
	newKeys := make(map[string]bool)
	for _, k := range ks {
		newKeys[k] = true
	}

	var buffer bytes.Buffer
	for k := range newKeys {
		buffer.WriteString(k)
		buffer.WriteByte('\n')
	}
	return os.WriteFile(k.fn, buffer.Bytes(), 0666)
}

func identifyLockHolders(filename string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("error identifying lock holder: works only on linux")
	}

	cmd := exec.Command("lsof", filename)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("error identifying lock holder: %w", err)
	}

	return string(out), nil
}
