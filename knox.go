// Package knox is a package to provide the basic types to be used across client and server.
package knox

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrACLDuplicateEntries = fmt.Errorf("Duplicate entries in ACL")
	ErrACLContainsNone     = fmt.Errorf("ACL contains None access")
	ErrACLEmptyPrincipal   = fmt.Errorf("Principals of type user, user group, machine, or machine prefix may not be empty.")

	ErrACLInvalidService               = fmt.Errorf("Service is invalid, must conform to 'spiffe://<domain>/<path>' format.")
	ErrACLInvalidServicePrefixURL      = fmt.Errorf("Service prefix is invalid URL, must conform to 'spiffe://<domain>/<path>/' format.")
	ErrACLInvalidServicePrefixNoSlash  = fmt.Errorf("Service prefix had no trailing slash, must conform to 'spiffe://<domain>/<path>/' format.")
	ErrACLInvalidServicePrefixTooShort = fmt.Errorf("Service prefix too short, path of namespace for prefix needs to be longer.")

	ErrInvalidKeyID       = fmt.Errorf("KeyID can only contain alphanumeric characters, colons, and underscores.")
	ErrInvalidVersionHash = fmt.Errorf("Hash does not match")

	ErrInactiveToPrimary = fmt.Errorf("Version must be Active to promote to Primary")
	ErrPrimaryToActive   = fmt.Errorf("Primary Key can not be demoted. Specify Active key to promote.")
	ErrPrimaryToInactive = fmt.Errorf("Version must be Active to demote to Inactive")

	ErrMulitplePrimary = fmt.Errorf("More than one Primary key")
	ErrSameVersionID   = fmt.Errorf("Repeated Version ID")

	ErrInvalidStatus      = fmt.Errorf("Invalid Status")
	ErrKeyVersionNotFound = fmt.Errorf("Key version not found")
	ErrKeyIDNotFound      = fmt.Errorf("KeyID not found")
	ErrKeyExists          = fmt.Errorf("Key Exists")
)

const (
	spiffeScheme = "spiffe"
)

// InvalidTypeError is an error for to throw when in the json conversion.
type invalidTypeError struct {
	badType string
}

func (e invalidTypeError) Error() string {
	return "json: Invalid " + e.badType + " to convert"
}

// VersionStatus is an enum to determine that state of a single Key Version.
// This is related to key rotation.
type VersionStatus int

// A PrincipalValidator is a function that applies to a principal type and string,
// and validates that the string is a valid principal for the given type.
type PrincipalValidator func(pt PrincipalType, id string) error

const (
	// Primary is the main key version. There is exactly one in a given KeyVersionList.
	Primary VersionStatus = iota
	// Active represents Key Versions still in use, but not Primary.
	Active
	// Inactive represents Key Versions no longer in use.
	Inactive
)

// UnmarshalJSON parses JSON input to set an VersionStatus.
func (s *VersionStatus) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"Primary"`:
		*s = Primary
	case `"Active"`:
		*s = Active
	case `"Inactive"`:
		*s = Inactive
	default:
		return invalidTypeError{"VersionStatus"}
	}
	return nil
}

// MarshalJSON returns the JSON representation of an VersionStatus.
func (s VersionStatus) MarshalJSON() ([]byte, error) {
	switch s {
	case Primary:
		return json.Marshal("Primary")
	case Active:
		return json.Marshal("Active")
	case Inactive:
		return json.Marshal("Inactive")
	default:
		return nil, invalidTypeError{"VersionStatus"}
	}
}

// PrincipalType is an attribute of ACLs that specifies what type of Principal
// is represented. This allows for users and machines to be bucketed together.
type PrincipalType int

const (
	// Unknown represents a bad PrincipalType that cannot be marshaled
	Unknown PrincipalType = -1
	// User represents a single LDAP User.
	User = iota
	// UserGroup represents an LDAP security group.
	UserGroup
	// Machine represents the host of a machine.
	Machine
	// MachinePrefix represents a prefix to match multiple machines.
	MachinePrefix
	// Service represents a service via SPIFFE ID.
	Service
	// ServicePrefix represents a prefix to match multiple SPIFFE IDs.
	ServicePrefix
)

// UnmarshalJSON parses JSON input to set an PrincipalType.
func (s *PrincipalType) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"User"`:
		*s = User
	case `"UserGroup"`:
		*s = UserGroup
	case `"Machine"`:
		*s = Machine
	case `"MachinePrefix"`:
		*s = MachinePrefix
	case `"Service"`:
		*s = Service
	case `"ServicePrefix"`:
		*s = ServicePrefix
	default:
		// To ensure compatibilty in the event of new PrincipalTypes, don't
		// throw an error. Instead just create a bogus Type. When displaying
		// the ACL to the user, fail on the single entry. GetKey & GetACL will work.
		*s = Unknown
	}
	return nil
}

// MarshalJSON returns the JSON representation of an PrincipalType.
func (s PrincipalType) MarshalJSON() ([]byte, error) {
	switch s {
	case User:
		return json.Marshal("User")
	case UserGroup:
		return json.Marshal("UserGroup")
	case Machine:
		return json.Marshal("Machine")
	case MachinePrefix:
		return json.Marshal("MachinePrefix")
	case Service:
		return json.Marshal("Service")
	case ServicePrefix:
		return json.Marshal("ServicePrefix")
	case Unknown:
		// Explicitly prevent unrecognized PrincipalTypes from being marshaled
		return nil, invalidTypeError{"PrincipalType"}
	default:
		return nil, invalidTypeError{"PrincipalType"}
	}
}

// IsValidPrincipal verifies that the given id string matches our expectations
// for what a principal should look like given the principal type. For example,
// a service principal should be a valid SPIFFE ID.
func (s PrincipalType) IsValidPrincipal(id string, extraValidators []PrincipalValidator) error {
	// Empty principals are invalid. Note we must deny addition of ACLs with
	// empty MachinePrefix to prevent abuse. An empty prefix would grant *every*
	// client access, which we don't support in Knox (if it's not a secret it
	// doesn't belong in Knox). For other types of principals, an empty string is
	// also invalid (though would not broadly open up access).
	if id == "" {
		return ErrACLEmptyPrincipal
	}

	// Apply additional validation for service and service prefix principals.
	switch s {
	case Service, ServicePrefix:
		// For Service principals and prefixes, verify that id looks like a valid SPIFFE ID.
		parsed, err := url.Parse(id)
		if err != nil || parsed.Scheme != spiffeScheme || parsed.Host == "" {
			return ErrACLInvalidServicePrefixURL
		}

		// Prefixes must also end in "/" as we don't allow prefixes to match inside
		// of a path component, to avoid perfixes like "foo/bar" also matching
		// things like "foo/barbaz" even though it should only match "foo/bar/baz".
		endsWithSlash := strings.HasSuffix(id, "/")
		if s == ServicePrefix && !endsWithSlash {
			return ErrACLInvalidServicePrefixNoSlash
		}
	}

	for _, extraValidator := range extraValidators {
		err := extraValidator(s, id)
		if err != nil {
			return err
		}
	}

	return nil
}

// ServicePrefixPathComponentsValidator is an extra validator that can be applied
// to ensure that service prefixes have a certain minimum length, e.g. to prevent
// allow the prefix to be a full domain.
func ServicePrefixPathComponentsValidator(minPathComponents int) PrincipalValidator {
	return func(pt PrincipalType, id string) error {
		if pt != ServicePrefix {
			return nil
		}

		parsed, err := url.Parse(id)
		if err != nil || parsed.Scheme != spiffeScheme || parsed.Host == "" {
			return ErrACLInvalidServicePrefixURL
		}

		// Trim leading and trailing slashes, and count remaining slashes to determine
		// the number of components in the namespace path.
		trimmed := strings.Trim(parsed.Path, "/")

		// If result is empty, it was zero components (e.g. prefix was "/").
		components := 0
		if trimmed != "" {
			components = strings.Count(trimmed, "/") + 1
		}

		if components < minPathComponents {
			return ErrACLInvalidServicePrefixTooShort
		}

		return nil
	}
}

// AccessType represents what kind of Access is granted in a key's ACL.
type AccessType int

const (
	// None denotes no access.
	None AccessType = iota
	// Read denotes the ability to read key data.
	Read
	// Write denotes the ability to add key versions and perform rotation.
	Write
	// Admin denotes the ability to delete the key and modify the ACL.
	Admin
)

// UnmarshalJSON parses JSON input to set an AccessType.
func (s *AccessType) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"Read"`:
		*s = Read
	case `"Write"`:
		*s = Write
	case `"Admin"`:
		*s = Admin
	case `"None"`:
		*s = None
	default:
		return invalidTypeError{"AccessType"}
	}
	return nil
}

// MarshalJSON returns the JSON representation of an AccessType.
func (s AccessType) MarshalJSON() ([]byte, error) {
	switch s {
	case Read:
		return json.Marshal("Read")
	case Write:
		return json.Marshal("Write")
	case Admin:
		return json.Marshal("Admin")
	case None:
		return json.Marshal("None")
	default:
		return nil, invalidTypeError{"AccessType"}
	}
}

// CanAccess uses a principal's AccessType to determine if the principal can
// access a given resource.
func (s AccessType) CanAccess(resource AccessType) bool {
	return s >= resource
}

// ACL is a list of access information that provides authorization information
// for a specific key.
type ACL []Access

// Access is a specific access grant as a part of an ACL specifying one
// principal's or a group of principals' granted acccess.
type Access struct {
	Type       PrincipalType `json:"type"`
	ID         string        `json:"id"`
	AccessType AccessType    `json:"access"`
}

// Validate ensures the ACL is of valid form. Not specifying the same group
// or id more than once.
func (acl ACL) Validate() error {
	for i, a := range acl {
		if a.AccessType == None {
			return ErrACLContainsNone
		}
		for j, b := range acl {
			if i != j && a.ID == b.ID && a.Type == b.Type {
				return ErrACLDuplicateEntries
			}
		}
	}
	return nil
}

// Add appends an access to the ACL. It does so by overwriting any existing access
// that principal or group may have had.
func (acl ACL) Add(a Access) ACL {
	for i, b := range acl {
		if b.Type == a.Type && a.ID == b.ID {
			if a.AccessType == None {
				return append(acl[:i], acl[i+1:]...)
			}
			newACL := make([]Access, len(acl))
			copy(newACL, acl)
			newACL[i] = a
			return newACL
		}
	}
	if a.AccessType == None {
		return acl
	}
	return append(acl, a)
}

// KeyVersion is a specific version of a Key. All attributes should be immutable
// except status.
type KeyVersion struct {
	ID           uint64        `json:"id"`
	Data         []byte        `json:"data"`
	Status       VersionStatus `json:"status"`
	CreationTime int64         `json:"ts"`
}

// KeyVersionList represents the list of versions of a key. This will grow as the
// key is rotated.
type KeyVersionList []KeyVersion

// Len, Swap, and Less are included to provide a consistant ordering for Key
// Version lists. This is necessary to hash the list consistantly.

// Len returns the length of the key version list.
func (kvl KeyVersionList) Len() int {
	return len(kvl)
}

// Swap swaps two elements in the list
func (kvl KeyVersionList) Swap(i, j int) {
	kvl[i], kvl[j] = kvl[j], kvl[i]
}

// Less determines where a key version is in an ordered list.
func (kvl KeyVersionList) Less(i, j int) bool {
	if kvl[i].Status == kvl[j].Status {
		return kvl[i].ID < kvl[j].ID
	}
	return kvl[i].Status < kvl[j].Status
}

// Key represents the Primary element of Knox.
type Key struct {
	ID          string         `json:"id"`
	ACL         ACL            `json:"acl"`
	VersionList KeyVersionList `json:"versions"`
	VersionHash string         `json:"hash"`
	Path        string         `json:"path,omitempty"`
}

// Validate calls makes sure all attributes of key are in good state.
func (k Key) Validate() error {
	// Check keyID characters
	re := regexp.MustCompile("^[a-zA-Z0-9_:]+$")
	if !re.MatchString(k.ID) {
		return ErrInvalidKeyID
	}

	aclErr := k.ACL.Validate()
	if aclErr != nil {
		return aclErr
	}
	vlistErr := k.VersionList.Validate()
	if vlistErr != nil {
		return vlistErr
	}
	if k.VersionHash != k.VersionList.Hash() {
		return ErrInvalidVersionHash
	}
	return nil
}

// GetActive returns the active keys in a KeyVersionList.
func (kvl KeyVersionList) GetActive() KeyVersionList {
	var ks KeyVersionList
	for _, k := range kvl {
		if k.Status == Active || k.Status == Primary {
			ks = append(ks, k)
		}
	}
	return ks
}

// GetPrimary returns the primary key in a KeyVersionList.
func (kvl KeyVersionList) GetPrimary() *KeyVersion {
	for _, k := range kvl {
		if k.Status == Primary {
			return &k
		}
	}
	// This should never be reached given a valid KVL.
	return nil
}

// Validate checks that key versions are unique and that there is exactly one
// Primary key.
func (kvl KeyVersionList) Validate() error {
	primaryCount := 0
	versionToData := map[uint64][]byte{}
	for _, kv := range kvl {
		if kv.Status == Primary {
			primaryCount++
		}
		if _, ok := versionToData[kv.ID]; ok {
			return ErrSameVersionID
		}
		versionToData[kv.ID] = kv.Data
	}
	if primaryCount != 1 {
		return ErrMulitplePrimary
	}
	return nil
}

// Hash computes the Sha256 hash of the ordered key versions.
// The hash ordering is the Primary version id followed by all
// Active version id in numeric order.
func (kvl KeyVersionList) Hash() string {
	sizeInt64 := 8
	sort.Sort(kvl)
	buf := make([]byte, sizeInt64*len(kvl))
	offset := 0
	for _, kv := range kvl {
		if kv.Status != Inactive {
			binary.LittleEndian.PutUint64(buf[offset:], kv.ID)
			offset += sizeInt64
		}
	}
	hash := sha256.Sum256(buf)
	return hex.EncodeToString(hash[0:32])

}

// Update changes the status of a particular key version. It also updates any
// other key versions that need to be updated. Acceptable changes are
// Active -> Primary, Active -> Inactive, and Inactive -> Active.
func (kvl KeyVersionList) Update(versionID uint64, s VersionStatus) (KeyVersionList, error) {
	for i, v := range kvl {
		if v.ID == versionID {
			switch s {
			case Primary:
				if v.Status != Active {
					return nil, ErrInactiveToPrimary
				}
				for j, v2 := range kvl {
					if v2.Status == Primary {
						kvl[j].Status = Active
					}
				}
				kvl[i].Status = Primary
			case Active:
				if v.Status != Inactive {
					return nil, ErrPrimaryToActive
				}
				kvl[i].Status = Active
			case Inactive:
				if v.Status != Active {
					return nil, ErrPrimaryToInactive
				}
				kvl[i].Status = Inactive
			}
			return kvl, nil
		}
	}
	return nil, ErrKeyVersionNotFound

}

// Principal is a person, machine, or process that accesses an object.
// This interface is currently defined for people and machines.
type Principal interface {
	CanAccess(ACL, AccessType) bool
	GetID() string
	Type() string
}

// PrincipalMux provides a Principal Interface over multiple Principals.
type PrincipalMux struct {
	// The default principal to use in the mux.
	defaultPrincipal Principal

	// All principals being muxed, including the default, indexed by provider.
	allPrincipals map[string]Principal
}

// CanAccess will check the principals in order of adding, and the first
// Principal that provides at least the AccessType requested will be used.
func (p PrincipalMux) CanAccess(acl ACL, accessType AccessType) bool {
	for _, p := range p.allPrincipals {
		if p.CanAccess(acl, accessType) {
			return true
		}
	}
	return false
}

// GetID returns the ID of the default principal.
func (p PrincipalMux) GetID() string {
	return p.defaultPrincipal.GetID()
}

// GetIDs returns all registered IDs from the principals that are muxed.
func (p PrincipalMux) GetIDs() []string {
	ids := []string{}
	for _, principal := range p.allPrincipals {
		ids = append(ids, principal.GetID())
	}
	return ids
}

// Type returns the underlying type of a principal, for logging/debugging purposes.
func (p PrincipalMux) Type() string {
	if len(p.allPrincipals) == 1 {
		return p.defaultPrincipal.Type()
	}

	types := []string{}
	for provider, principal := range p.allPrincipals {
		types = append(types, fmt.Sprintf("%s=>%s", provider, principal.Type()))
	}

	// Outputs a string like 'mux[foo=>user, bar=>service]'.
	return fmt.Sprintf("mux[%s]", strings.Join(types, ","))
}

// Default returns the first registered Principal.
func (p PrincipalMux) Default() Principal {
	return p.defaultPrincipal
}

// NewPrincipalMux returns a Principal that represents many principals.
func NewPrincipalMux(defaultPrincipal Principal, allPrincipals map[string]Principal) Principal {
	return PrincipalMux{
		defaultPrincipal: defaultPrincipal,
		allPrincipals:    allPrincipals,
	}
}

// These are the error codes for use in server responses.
const (
	OKCode = iota
	InternalServerErrorCode
	KeyIdentifierExistsCode
	KeyVersionDoesNotExistCode
	KeyIdentifierDoesNotExistCode
	UnauthenticatedCode
	UnauthorizedCode
	NotYetImplementedCode
	NotFoundCode
	NoKeyIDCode
	NoKeyDataCode
	BadRequestDataCode
	BadKeyFormatCode
	BadPrincipalIdentifier
)

// Response is the format for responses from the api server.
type Response struct {
	Status    string      `json:"status"`
	Code      int         `json:"code"`
	Host      string      `json:"host"`
	Timestamp int64       `json:"ts"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
}
