package keydb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pinterest/knox"
)

var ErrDBVersion = fmt.Errorf("DB version does not match")

// DBKey is a struct for the json serialization of keys in the database.
type DBKey struct {
	ID          string          `json:"id"`
	ACL         knox.ACL        `json:"acl"`
	VersionList []EncKeyVersion `json:"versions"`
	VersionHash string          `json:"hash"`
	// The version should be set by the db provider and is not part of the data.
	DBVersion int64 `json:"-"`
}

// Copy provides a deep copy of database keys so that VersionLists can be edited in a copy.
func (k *DBKey) Copy() *DBKey {
	versionList := make([]EncKeyVersion, len(k.VersionList))
	copy(versionList, k.VersionList)
	acl := make([]knox.Access, len(k.ACL))
	copy(acl, k.ACL)
	return &DBKey{
		ID:          k.ID,
		ACL:         acl,
		VersionList: versionList,
		VersionHash: k.VersionHash,
		DBVersion:   k.DBVersion,
	}
}

// EncKeyVersion is a struct for encrypting key data
type EncKeyVersion struct {
	ID             uint64             `json:"id"`
	EncData        []byte             `json:"data"`
	Status         knox.VersionStatus `json:"status"`
	CreationTime   int64              `json:"ts"`
	CryptoMetadata []byte             `json:"crypt"`
}

// DB is the underlying database connection that KeyDB uses for all of its operations.
//
// This interface should not contain any business logic and should only deal with formatting
// and database specific logic.
type DB interface {
	// Get returns the key specified by the ID.
	Get(id string) (*DBKey, error)
	// GetAll returns all of the keys in the database.
	GetAll() ([]DBKey, error)

	// Update makes an update to DBKey indexed by its ID.
	// It will fail if the key has been changed since the specified version.
	Update(key *DBKey) error
	// Add adds the key(s) to the DB (it will fail if the key id exists).
	Add(keys ...*DBKey) error
	// Remove permanently removes the key specified by the ID.
	Remove(id string) error
}

// NewTempDB creates a new TempDB with no data.
func NewTempDB() DB {
	return &TempDB{}
}

// TempDB is an in memory DB that does no replication across servers and starts
// out fresh everytime. It is written for testing and simple dev work.
type TempDB struct {
	sync.RWMutex
	keys []DBKey
	err  error
}

// SetError is used to set the error the TempDB for testing purposes.
func (db *TempDB) SetError(err error) {
	db.Lock()
	defer db.Unlock()
	db.err = err
}

// Get gets stored db key from TempDB.
func (db *TempDB) Get(id string) (*DBKey, error) {
	db.RLock()
	defer db.RUnlock()
	if db.err != nil {
		return nil, db.err
	}
	for _, k := range db.keys {
		if k.ID == id {
			return &k, nil
		}
	}
	return nil, knox.ErrKeyIDNotFound
}

// GetAll gets all keys from TempDB.
func (db *TempDB) GetAll() ([]DBKey, error) {
	db.RLock()
	defer db.RUnlock()
	if db.err != nil {
		return nil, db.err
	}
	return db.keys, nil
}

// Update looks for an existing key and updates the key in the database.
func (db *TempDB) Update(key *DBKey) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for i, dbk := range db.keys {
		if dbk.ID == key.ID {
			if dbk.DBVersion != key.DBVersion {
				return ErrDBVersion
			}
			k := key.Copy()
			k.DBVersion = time.Now().UnixNano()
			db.keys[i] = *k
			return nil
		}
	}
	return knox.ErrKeyIDNotFound
}

// Add adds the key(s) to the DB (it will fail if the key id exists).
func (db *TempDB) Add(keys ...*DBKey) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for _, key := range keys {
		for _, oldK := range db.keys {
			if oldK.ID == key.ID {
				return knox.ErrKeyExists
			}
		}
	}
	for _, key := range keys {
		k := key.Copy()
		k.DBVersion = time.Now().UnixNano()

		db.keys = append(db.keys, *k)
	}
	return nil

}

// Remove will remove the key id from the database.
func (db *TempDB) Remove(id string) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for i, k := range db.keys {
		if k.ID == id {
			db.keys = append(db.keys[:i], db.keys[i+1:]...)
			return nil
		}
	}
	return knox.ErrKeyIDNotFound
}

// SQLDB provides a generic way to use SQL providers as Knox DBs.
type SQLDB struct {
	getStmt    *sql.Stmt
	getAllStmt *sql.Stmt
	UpdateStmt *sql.Stmt
	AddStmt    *sql.Stmt
	RemoveStmt *sql.Stmt
	db         sql.DB
}

var sqlCreateKeys = `CREATE TABLE IF NOT EXISTS secrets (
	id VARCHAR(512) PRIMARY KEY,
	acl TEXT NOT NULL,
	version_hash TEXT NOT NULL,
	versions TEXT NOT NULL,
	last_updated BIGINT NOT NULL
);`

// NewPostgreSQLDB will create a SQLDB with the necessary statements for using postgres.
func NewPostgreSQLDB(sqlDB *sql.DB) (DB, error) {
	db := &SQLDB{}
	var err error
	_, err = sqlDB.Exec(sqlCreateKeys)
	if err != nil {
		return nil, err
	}
	db.getStmt, err = sqlDB.Prepare("SELECT id, acl, version_hash, versions, last_updated FROM secrets WHERE id=$1")
	if err != nil {
		return nil, err
	}
	db.getAllStmt, err = sqlDB.Prepare("SELECT id, acl, version_hash, versions, last_updated FROM secrets")
	if err != nil {
		return nil, err
	}
	db.UpdateStmt, err = sqlDB.Prepare("UPDATE secrets SET versions=$1, version_hash=$2,last_updated=$3,acl=$4 WHERE id=$5 AND last_updated=$6")
	if err != nil {
		return nil, err
	}
	db.AddStmt, err = sqlDB.Prepare("INSERT INTO secrets (id, acl, versions, version_hash, last_updated) VALUES ($1,$2,$3,$4,$5)")
	if err != nil {
		return nil, err
	}
	db.RemoveStmt, err = sqlDB.Prepare("DELETE FROM secrets WHERE id=$1")
	if err != nil {
		return nil, err
	}
	return db, nil
}

// NewSQLDB creates a table and prepared statements suitable for mysql and sqlite databases.
func NewSQLDB(sqlDB *sql.DB) (DB, error) {
	db := &SQLDB{}
	var err error
	_, err = sqlDB.Exec(sqlCreateKeys)
	if err != nil {
		return nil, err
	}
	db.getStmt, err = sqlDB.Prepare("SELECT id, acl, version_hash, versions, last_updated FROM secrets WHERE id=?")
	if err != nil {
		return nil, err
	}
	db.getAllStmt, err = sqlDB.Prepare("SELECT id, acl, version_hash, versions, last_updated FROM secrets")
	if err != nil {
		return nil, err
	}
	db.UpdateStmt, err = sqlDB.Prepare("UPDATE secrets SET versions=?, version_hash=?,last_updated=?,acl=? WHERE id=? AND last_updated=?")
	if err != nil {
		return nil, err
	}
	db.AddStmt, err = sqlDB.Prepare("INSERT INTO secrets (id, acl, versions, version_hash, last_updated) VALUES (?,?,?,?,?)")
	if err != nil {
		return nil, err
	}
	db.RemoveStmt, err = sqlDB.Prepare("DELETE FROM secrets WHERE id=?")
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Get will return the key given its key ID.
func (db *SQLDB) Get(id string) (*DBKey, error) {
	var key DBKey
	var acl, versions []byte
	err := db.getStmt.QueryRow(id).Scan(&key.ID, &acl, &key.VersionHash, &versions, &key.DBVersion)
	if err != nil {
		return nil, knox.ErrKeyIDNotFound
	}
	err = json.Unmarshal(acl, &key.ACL)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(versions, &key.VersionList)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// GetAll returns all of the keys in the database.
func (db *SQLDB) GetAll() ([]DBKey, error) {
	var keys []DBKey
	rows, err := db.getAllStmt.Query()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var key DBKey
		var acl, versions []byte
		err := rows.Scan(&key.ID, &acl, &key.VersionHash, &versions, &key.DBVersion)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(acl, &key.ACL)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(versions, &key.VersionList)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// Update makes an update to DBKey indexed by its ID.
// It will fail if the key has been changed since the specified version.
func (db *SQLDB) Update(key *DBKey) error {
	versions, err := json.Marshal(key.VersionList)
	if err != nil {
		return err
	}
	acl, err := json.Marshal(key.ACL)
	if err != nil {
		return err
	}
	updateTime := time.Now().UnixNano()
	r, err := db.UpdateStmt.Exec(versions, key.VersionHash, updateTime, acl, key.ID, key.DBVersion)
	if err != nil {
		return err
	}
	affected, err := r.RowsAffected()
	if err != nil {
		// This likely shouldn't return an error if rows affected is not implemented.
		return err
	}
	if affected == 0 {
		rs, err := db.getStmt.Query(key.ID)
		if err != nil {
			return err
		}
		defer rs.Close()
		if !rs.Next() {
			return knox.ErrKeyIDNotFound
		}
		return ErrDBVersion
	}
	return nil
}

// Add adds the key version (it will fail if the key id exists).
func (db *SQLDB) Add(keys ...*DBKey) error {
	// For loop is the dumbest way to this; should refactor into one query/transaction.
	for _, key := range keys {
		versions, err := json.Marshal(key.VersionList)
		if err != nil {
			return err
		}
		acl, err := json.Marshal(key.ACL)
		if err != nil {
			return err
		}
		updateTime := time.Now().UnixNano()
		_, err = db.AddStmt.Exec(key.ID, acl, versions, key.VersionHash, updateTime)
		if err != nil {
			// Not sure how to properly differentiate here...
			return knox.ErrKeyExists
		}
		// Not checking rows affected because I assume the db will return an error on primary key collision.
	}
	return nil
}

// Remove permanently removes the key specified by the ID.
func (db *SQLDB) Remove(id string) error {
	r, err := db.RemoveStmt.Exec(id)
	if err != nil {
		return err
	}
	affected, err := r.RowsAffected()
	if err != nil {
		// This likely shouldn't return an error if rows affected is not implemented.
		return err
	}
	if affected == 0 {
		return knox.ErrKeyIDNotFound
	}
	return nil
}
