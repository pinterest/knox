package keydb

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/pinterest/knox"
	/* For DB testing:
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	*/)

func newEncKeyVersion(d []byte, s knox.VersionStatus) EncKeyVersion {
	version := EncKeyVersion{}
	version.EncData = d
	version.Status = s
	version.CreationTime = time.Now().UnixNano()
	// This is only 63 bits of randomness, but it appears to be the fastest way.
	version.ID = uint64(rand.Int63())
	return version
}

func newDBKey(id string, d []byte, version int64) DBKey {
	key := DBKey{}
	key.ID = id

	key.ACL = knox.ACL{}
	key.DBVersion = version

	key.VersionList = []EncKeyVersion{newEncKeyVersion(d, knox.Primary)}
	return key
}

func TestTemp(t *testing.T) {
	db := NewTempDB()
	timeout := 100 * time.Millisecond
	TesterAddGet(t, db, timeout)
	TesterAddUpdate(t, db, timeout)
	TesterAddRemove(t, db, timeout)
}

func TestDBCopy(t *testing.T) {
	a := knox.Access{}
	v := EncKeyVersion{}
	r := DBKey{
		ID:          "id1",
		ACL:         []knox.Access{a},
		VersionList: []EncKeyVersion{v},
		VersionHash: "hash1",
		DBVersion:   1,
	}
	b := r.Copy()
	b.ID = "id2"
	if r.ID == b.ID {
		t.Error("Ids are equal after copy")
	}
	b.DBVersion = 2
	if r.DBVersion == b.DBVersion {
		t.Error("DBVersion are equal after copy")
	}
	b.VersionHash = "hash2"
	if r.VersionHash == b.VersionHash {
		t.Error("VersionHash are equal after copy")
	}
	b.ACL[0].ID = "pi"
	if r.ACL[0].ID == b.ACL[0].ID {
		t.Error("ACL[0].ID are equal after copy")
	}
	b.VersionList[0].ID = 17
	if r.VersionList[0].ID == b.VersionList[0].ID {
		t.Error("VersionList[0].ID are equal after copy")
	}

}

/*
TODO(devinlundberg): figure out how to make these work as unit tests (or build out a way to do integration tests)

// TestMySQL runs all keydb tests on a mysqldb. It requires an empty db.
func TestMySQL(t *testing.T) {
	d, err := sql.Open("mysql", "user:password@/test")
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewSQLDB(d)
	if err != nil {
		t.Fatal(err)
	}
	timeout := 100 * time.Millisecond
	TesterAddGet(t, db, timeout)
	TesterAddUpdate(t, db, timeout)
	TesterAddRemove(t, db, timeout)
}

// TestSQLite runs all keydb tests on a file it requires this file to be empty.
func TestSQLite(t *testing.T) {
	d, err := sql.Open("sqlite3", "foo.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewSQLDB(d)
	if err != nil {
		t.Fatal(err)
	}
	timeout := 100 * time.Millisecond
	TesterAddGet(t, db, timeout)
	TesterAddUpdate(t, db, timeout)
	TesterAddRemove(t, db, timeout)
}

// TestPostgreSQL runs all keydb tests on a postgres db. It requires an empty db.
func TestPostgreSQL(t *testing.T) {
	d, err := sql.Open("postgres", "user=user dbname=test sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewPostgreSQLDB(d)
	if err != nil {
		t.Fatal(err)
	}
	timeout := 100 * time.Millisecond
	TesterAddGet(t, db, timeout)
	TesterAddUpdate(t, db, timeout)
	TesterAddRemove(t, db, timeout)
}
*/
func TestTempErrs(t *testing.T) {
	db := &TempDB{}
	err := fmt.Errorf("Does not compute... EXTERMINATE! EXTERMINATE!")
	db.SetError(err)
	TesterErrs(t, db, err)
}

func TesterErrs(t *testing.T, db DB, expErr error) {
	k := newDBKey("TesterErrs1", []byte("ab"), 0)
	go func() {
		_, err := db.GetAll()
		if err != expErr {
			t.Errorf("%s does not equal %s", err, expErr)
		}
	}()
	go func() {
		err := db.Add(&k)
		if err != expErr {
			t.Errorf("%s does not equal %s", err, expErr)
		}
	}()
	go func() {
		err := db.Remove(k.ID)
		if err != expErr {
			t.Errorf("%s does not equal %s", err, expErr)
		}
	}()
	go func() {
		err := db.Update(&k)
		if err != expErr {
			t.Errorf("%s does not equal %s", err, expErr)
		}
	}()
	go func() {
		_, err := db.Get(k.ID)
		if err != expErr {
			t.Errorf("%s does not equal %s", err, expErr)
		}
	}()
}

func TesterAddGet(t *testing.T, db DB, timeout time.Duration) {
	origKeys, err := db.GetAll()
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	k := newDBKey("TestAddGet1", []byte("a"), 0)
	err = db.Add(&k)
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	complete := false
	timer := time.Tick(timeout)
	for !complete {
		select {
		case <-timer:
			t.Fatal("Timed out waiting TestAddGet1 to get added")
		case <-time.Tick(1 * time.Millisecond):
			newK, err := db.Get(k.ID)
			if err == nil {
				if newK.ID != k.ID {
					t.Fatalf("%s does not equal %s", newK.ID, k.ID)
				}
				if len(newK.VersionList) != 1 {
					t.Fatalf("%d does not equal 1", len(newK.VersionList))
				}
				if newK.VersionList[0].EncData[0] != k.VersionList[0].EncData[0] {
					t.Fatalf("%c does not equal %c", newK.VersionList[0].EncData[0], k.VersionList[0].EncData[0])
				}
				complete = true
			} else if err != knox.ErrKeyIDNotFound {
				t.Fatal(err)
			}
		}
	}
	keys, err := db.GetAll()
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	if len(keys) != len(origKeys)+1 {
		t.Fatal("key list length did not grow by 1")
	}

	err = db.Add(&k)
	if err != knox.ErrKeyExists {
		t.Fatalf("%s does not equal %s", err, knox.ErrKeyExists)
	}
}

func TesterAddUpdate(t *testing.T, db DB, timeout time.Duration) {
	_, err := db.GetAll()
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	k := newDBKey("TesterAddUpdate1", []byte("a"), 0)
	err = db.Update(&k)
	if err != knox.ErrKeyIDNotFound {
		t.Fatalf("%s does not equal %s", err, knox.ErrKeyIDNotFound)
	}
	err = db.Add(&k)
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	complete := false
	timer := time.Tick(timeout)
	var version int64
	for !complete {
		select {
		case <-timer:
			t.Fatal("Timed out waiting TesterAddUpdate1 to get added")
		case <-time.Tick(1 * time.Millisecond):
			newK, err := db.Get(k.ID)
			if err == nil {
				version = newK.DBVersion
				complete = true
			} else if err != knox.ErrKeyIDNotFound {
				t.Fatal(err)
			}
		}
	}
	if version == 0 {
		t.Fatal("version number did not initialize to non zero value")
	}
	err = db.Update(&k)
	if err != ErrDBVersion {
		t.Fatalf("%s does not equal %s", err, ErrDBVersion)
	}

	k.VersionList = append(k.VersionList, newEncKeyVersion([]byte("b"), knox.Active))
	k.DBVersion = version
	err = db.Update(&k)
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	complete = false
	timer = time.Tick(timeout)
	for !complete {
		select {
		case <-timer:
			t.Fatal("Timed out waiting TesterAddUpdate1 to get added")
		case <-time.Tick(1 * time.Millisecond):
			newK, err := db.Get(k.ID)
			if err == nil && len(newK.VersionList) != 1 {
				if len(newK.VersionList) != 2 {
					t.Fatalf("%d does not equal 2", len(newK.VersionList))
				}
				var pk, ak EncKeyVersion
				if newK.VersionList[0].Status == knox.Primary {
					pk = newK.VersionList[0]
					ak = newK.VersionList[1]
				} else {
					pk = newK.VersionList[1]
					ak = newK.VersionList[0]
				}
				if string(pk.EncData) != "a" {
					t.Fatalf("%s does not equal a", string(pk.EncData))
				}
				if string(ak.EncData) != "b" {
					t.Fatalf("%s does not equal b", string(ak.EncData))
				}
				version = newK.DBVersion
				complete = true
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TesterAddRemove(t *testing.T, db DB, timeout time.Duration) {
	_, err := db.GetAll()
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	k := newDBKey("TesterAddRemove1", []byte("a"), 0)
	err = db.Remove(k.ID)
	if err != knox.ErrKeyIDNotFound {
		t.Fatalf("%s does not equal %s", err, knox.ErrKeyIDNotFound)
	}
	err = db.Add(&k)
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	complete := false
	timer := time.Tick(timeout)
	for !complete {
		select {
		case <-timer:
			t.Fatal("Timed out waiting TestAddGet1 to get added")
		case <-time.Tick(1 * time.Millisecond):
			_, err := db.Get(k.ID)
			if err == nil {
				complete = true
			} else if err != knox.ErrKeyIDNotFound {
				t.Fatal(err)
			}
		}
	}
	err = db.Remove(k.ID)
	if err != nil {
		t.Fatalf("%s not nil", err)
	}
	complete = false
	timer = time.Tick(timeout)
	for !complete {
		select {
		case <-timer:
			t.Fatal("Timed out waiting TestAddGet1 to get added")
		case <-time.Tick(1 * time.Millisecond):
			_, err := db.Get(k.ID)
			if err == knox.ErrKeyIDNotFound {
				complete = true
			} else if err != knox.ErrKeyIDNotFound && err != nil {
				t.Fatal(err)
			}
		}
	}
}
