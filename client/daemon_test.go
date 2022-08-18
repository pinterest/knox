package client

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pinterest/knox"
)

var registeredFile = ".registered"
var keysDir = "/keys/"

// buildServer returns a server. Call Close when finished.
func buildServer(d *returnParameters) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.a(r)
		d.Lock()
		defer d.Unlock()
		w.WriteHeader(d.statusCode)
		w.Header().Set("Content-Type", "application/json")
		w.Write(d.data)
	}))
}

func setGoodResponse(params *returnParameters, data interface{}) error {
	resp := &knox.Response{
		Status:    "ok",
		Code:      knox.OKCode,
		Host:      "test",
		Timestamp: 1234567890,
		Message:   "",
		Data:      data,
	}
	d, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	params.setData(d)
	params.setCode(200)
	return nil
}

type returnParameters struct {
	sync.Mutex
	data       []byte
	statusCode int
	a          func(r *http.Request)
}

func (p *returnParameters) setData(d []byte) {
	p.Lock()
	defer p.Unlock()
	p.data = d
}

func (p *returnParameters) setCode(c int) {
	p.Lock()
	defer p.Unlock()
	p.statusCode = c
}

func (p *returnParameters) setFunc(a func(r *http.Request)) {
	p.Lock()
	defer p.Unlock()
	p.a = a
}

func setUpTest(t *testing.T) (*returnParameters, string, daemon) {
	var params returnParameters
	srv := buildServer(&params)
	addr := srv.Listener.Addr().String()
	if err := setGoodResponse(&params, ""); err != nil {
		t.Fatal("failed to initialize response params: " + err.Error())
	}
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	cli := knox.MockClient(addr)
	cli.KeyFolder = dir + keysDir
	d := daemon{
		dir:          dir,
		registerFile: registeredFile,
		keysDir:      keysDir,
		cli:          cli,
	}
	if err := d.initialize(); err != nil {
		t.Fatal("failed to initialize daemon: " + err.Error())
	}
	return &params, dir, d
}

func TearDownTest(dir string) {
	os.RemoveAll(dir)
}

func TestProcessKey(t *testing.T) {
	params, dir, d := setUpTest(t)
	defer TearDownTest(dir)
	expected := knox.Key{
		ID:          "testkey",
		ACL:         knox.ACL([]knox.Access{}),
		VersionList: knox.KeyVersionList{},
		VersionHash: "VersionHash",
	}
	if err := addRegisteredKey(expected.ID, d.registerFilename()); err != nil {
		t.Fatal("Failed to register key: " + err.Error())
	}
	params.setFunc(func(r *http.Request) {
		switch r.URL.Path {
		case "/v0/keys/":
			setGoodResponse(params, []string{expected.ID})
		case "/v0/keys/" + expected.ID + "/":
			setGoodResponse(params, expected)
		default:
			t.Fatal("Unexpected path:" + r.URL.Path)
		}
	})
	err := d.processKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if d.getKeyErrCount != uint64(0) {
		t.Fatalf("%d does not equal %d", d.getKeyErrCount, uint64(0))
	}

	ret, err := d.cli.CacheGetKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if ret.ID != expected.ID {
		t.Fatalf("%s does not equal %s", ret.ID, expected.ID)
	}
	if len(ret.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(ret.ACL), len(expected.ACL))
	}
	if len(ret.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(ret.VersionList), len(expected.VersionList))
	}
	if ret.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", ret.VersionHash, expected.VersionHash)
	}

	expected.VersionHash = "VersionHash2"
	err = d.processKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if d.getKeyErrCount != uint64(0) {
		t.Fatalf("%d does not equal %d", d.getKeyErrCount, uint64(0))
	}

	ret, err = d.cli.CacheGetKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if ret.ID != expected.ID {
		t.Fatalf("%s does not equal %s", ret.ID, expected.ID)
	}
	if len(ret.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(ret.ACL), len(expected.ACL))
	}
	if len(ret.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(ret.VersionList), len(expected.VersionList))
	}
	if ret.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", ret.VersionHash, expected.VersionHash)
	}
}

func TestUpdate(t *testing.T) {
	params, dir, d := setUpTest(t)
	defer TearDownTest(dir)
	expected := knox.Key{
		ID:          "testkey",
		ACL:         knox.ACL([]knox.Access{}),
		VersionList: knox.KeyVersionList{},
		VersionHash: "VersionHash",
	}
	if err := addRegisteredKey(expected.ID, d.registerFilename()); err != nil {
		t.Fatal("Failed to register key: " + err.Error())
	}

	err := d.registerKeyFile.Lock()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	keys, err := d.registerKeyFile.Get()
	err = d.registerKeyFile.Unlock()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d is not equal to 1", len(keys))
	}
	if keys[0] != expected.ID {
		t.Fatalf("%s does not equal %s", keys[0], expected.ID)
	}

	params.setFunc(func(r *http.Request) {
		switch r.URL.Path {
		case "/v0/keys/":
			if r.URL.RawQuery != expected.ID+"=" {
				t.Fatalf("%s does not equal %s", r.URL.RawQuery, expected.ID+"=")
			}
			setGoodResponse(params, []string{expected.ID})
		case "/v0/keys/" + expected.ID + "/":
			setGoodResponse(params, expected)
		default:
			t.Fatal("Unexpected path:" + r.URL.Path)
		}
	})
	err = d.update()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if d.getKeyErrCount != uint64(0) {
		t.Fatalf("%d does not equal %d", d.getKeyErrCount, uint64(0))
	}

	ret, err := d.cli.CacheGetKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if ret.ID != expected.ID {
		t.Fatalf("%s does not equal %s", ret.ID, expected.ID)
	}
	if len(ret.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(ret.ACL), len(expected.ACL))
	}
	if len(ret.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(ret.VersionList), len(expected.VersionList))
	}
	if ret.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", ret.VersionHash, expected.VersionHash)
	}

	keys, err = d.currentRegisteredKeys()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d is not equal to 1", len(keys))
	}
	if keys[0] != expected.ID {
		t.Fatalf("%s does not equal %s", keys[0], expected.ID)
	}

	// Do the same thing again to assert there were no changes
	params.setFunc(func(r *http.Request) {
		switch r.URL.Path {
		case "/v0/keys/":
			if r.URL.RawQuery != expected.ID+"="+expected.VersionHash {
				t.Fatalf("%s does not equal %s", r.URL.RawQuery, expected.ID+"="+expected.VersionHash)
			}
			setGoodResponse(params, []string{})
		case "/v0/keys/" + expected.ID + "/":
			t.Fatalf("Should not call for a key again")
		default:
			t.Fatal("Unexpected path:" + r.URL.Path)
		}
	})
	err = d.update()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if d.getKeyErrCount != uint64(0) {
		t.Fatalf("%d does not equal %d", d.getKeyErrCount, uint64(0))
	}

	ret, err = d.cli.CacheGetKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if ret.ID != expected.ID {
		t.Fatalf("%s does not equal %s", ret.ID, expected.ID)
	}
	if len(ret.ACL) != len(expected.ACL) {
		t.Fatalf("%d does not equal %d", len(ret.ACL), len(expected.ACL))
	}
	if len(ret.VersionList) != len(expected.VersionList) {
		t.Fatalf("%d does not equal %d", len(ret.VersionList), len(expected.VersionList))
	}
	if ret.VersionHash != expected.VersionHash {
		t.Fatalf("%s does not equal %s", ret.VersionHash, expected.VersionHash)
	}

	// Check what happens on an update
	newExpected := knox.Key{
		ID:          "testkey",
		ACL:         knox.ACL([]knox.Access{}),
		VersionList: knox.KeyVersionList{},
		VersionHash: "VersionHash2",
	}
	params.setFunc(func(r *http.Request) {
		switch r.URL.Path {
		case "/v0/keys/":
			if r.URL.RawQuery != expected.ID+"="+expected.VersionHash {
				t.Fatalf("%s does not equal %s", r.URL.RawQuery, expected.ID+"="+expected.VersionHash)
			}
			setGoodResponse(params, []string{expected.ID})
		case "/v0/keys/" + expected.ID + "/":
			setGoodResponse(params, newExpected)
		default:
			t.Fatal("Unexpected path:" + r.URL.Path)
		}
	})
	err = d.update()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if d.getKeyErrCount != uint64(0) {
		t.Fatalf("%d does not equal %d", d.getKeyErrCount, uint64(0))
	}

	ret, err = d.cli.CacheGetKey(expected.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if ret.ID != newExpected.ID {
		t.Fatalf("%s does not equal %s", ret.ID, newExpected.ID)
	}
	if len(ret.ACL) != len(newExpected.ACL) {
		t.Fatalf("%d does not equal %d", len(ret.ACL), len(newExpected.ACL))
	}
	if len(ret.VersionList) != len(newExpected.VersionList) {
		t.Fatalf("%d does not equal %d", len(ret.VersionList), len(newExpected.VersionList))
	}
	if ret.VersionHash != newExpected.VersionHash {
		t.Fatalf("%s does not equal %s", ret.VersionHash, newExpected.VersionHash)
	}

	keys, err = d.currentRegisteredKeys()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d is not equal to 1", len(keys))
	}
	if keys[0] != expected.ID {
		t.Fatalf("%s does not equal %s", keys[0], expected.ID)
	}
}

func addRegisteredKey(k, reg string) error {
	f, err := os.OpenFile(reg, os.O_APPEND|os.O_WRONLY, 0666)
	defer f.Close()
	if err != nil {
		return err
	}
	_, err = f.WriteString(k + "\n")
	return err
}

func TestCreateGet(t *testing.T) {
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	defer TearDownTest(dir)

	k := NewKeysFile(dir + "/TestCreateGet")
	_, err = k.Get()
	if err == nil {
		t.Fatal("error is nil for a bad key")
	}

	err = k.Add([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err := k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "a" {
		t.Fatalf("%s does not equal %s", ks[0], "a")
	}
}

func TestDuplicateAdd(t *testing.T) {
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	defer TearDownTest(dir)

	k := NewKeysFile(dir + "/TestDuplicateAdd")

	err = k.Add([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err := k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "a" {
		t.Fatalf("%s does not equal %s", ks[0], "a")
	}

	err = k.Overwrite([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err = k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "a" {
		t.Fatalf("%s does not equal %s", ks[0], "a")
	}
}

func TestAddRemove(t *testing.T) {
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	defer TearDownTest(dir)

	k := NewKeysFile(dir + "/TestAddRemove")

	err = k.Add([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err := k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "a" {
		t.Fatalf("%s does not equal %s", ks[0], "a")
	}

	err = k.Remove([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err = k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 0 {
		t.Fatalf("ks should have length 0 instead of %d", len(ks))
	}
}

func TestOverwrite(t *testing.T) {
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	defer TearDownTest(dir)
	k := NewKeysFile(dir + "/TestOverwrite")

	err = k.Add([]string{"a"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err := k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "a" {
		t.Fatalf("%s does not equal %s", ks[0], "a")
	}

	err = k.Overwrite([]string{"b"})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err = k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 1 {
		t.Fatalf("ks should have length 1 instead of %d", len(ks))
	}
	if ks[0] != "b" {
		t.Fatalf("%s does not equal %s", ks[0], "b")
	}
}

func TestBackwardsCompat(t *testing.T) {
	dir, err := ioutil.TempDir("", "knox-test")
	if err != nil {
		t.Fatal("Failed to create temp directory: " + err.Error())
	}
	defer TearDownTest(dir)
	fn := dir + "/TestBackwardsCompat"
	k := NewKeysFile(fn)
	err = ioutil.WriteFile(fn, []byte{}, defaultFilePermission)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = addRegisteredKey("1", fn)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = addRegisteredKey("2", fn)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = addRegisteredKey("3", fn)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	ks, err := k.Get()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(ks) != 3 {
		t.Fatalf("ks should have length 3 instead of %d", len(ks))
	}

	for _, key := range ks {
		if key != "1" && key != "2" && key != "3" {
			t.Fatalf("%s does not equal 1, 2, or 3", key)
		}
	}
}

func TestLockTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test must run on Linux")
		return
	}
	_, err := exec.LookPath("lsof")
	if err != nil {
		t.Fatal("lsof is not installed in path")
	}
	_, err = exec.LookPath("flock")
	if err != nil {
		t.Fatal("flock is not installed in path")
	}

	tmp, err := ioutil.TempDir("", "test-lock-timeout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	lockFile := path.Join(tmp, "lock")
	ioutil.WriteFile(lockFile, []byte{}, 0600)

	// Lock file in sub-process to create locking conflict
	locker, stdout, stderr := lockFileInSeparateProcess(t, lockFile, "300")
	defer func() {
		if locker.Process != nil {
			t.Log("Terminating locking subprocess...")

			syscall.Kill(-locker.Process.Pid, syscall.SIGKILL)

			// Print stdout/stderr from locking process for debugging
			allStdout, err := ioutil.ReadAll(stdout)
			allStderr, err := ioutil.ReadAll(stderr)
			t.Log(string(allStdout), err)
			t.Log(string(allStderr), err)
		}
	}()

	// Wait for subprocess to spin up
	time.Sleep(5 * time.Second)

	// Dump lock holder pre-timeout (useful to identify test failures)
	t.Log(identifyLockHolders(lockFile))

	// Try to acquire lock in this process and make sure we hit a timeout
	kf := NewKeysFile(lockFile)
	err = kf.Lock()
	if err == nil {
		t.Fatal("was able to acquire lock, but should not have been")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatal("got lock error, but error was not a timeout")
	}

	// Dump lock holder post-timeout (useful to identify test failures)
	t.Log(identifyLockHolders(lockFile))
}

func lockFileInSeparateProcess(t *testing.T, filename, seconds string) (*exec.Cmd, io.ReadCloser, io.ReadCloser) {
	// Spawn "flock" subprocess that will acquire and hold lock for us (up to N seconds)
	cmd := exec.Command("flock", filename, "sleep", seconds)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}

	return cmd, stdout, stderr
}
