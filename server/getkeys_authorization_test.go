package server

import (
	"testing"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/server/auth"
)

// Regression test for: GET /v0/keys/ (getKeysHandler, no query string) used to
// return every key ID in the instance via KeyManager.GetAllKeyIDs(), with no
// ACL check at all. Every other single-key route (getKeyHandler,
// deleteKeyHandler, putAccessHandler, ...) calls authorizeRequest(key,
// principal, ...) before returning anything; this bulk-listing route did not.
//
// Key IDs are not meant to be public: they routinely encode team, project, or
// vendor names (e.g. "stripe_prod_api_key"), which is exactly the kind of
// information a secrets manager's own ACLs are meant to keep scoped to
// authorized principals -- it is valuable reconnaissance for an attacker who
// holds any valid Knox credential at all, however low-privileged.
func TestGetAllKeyIDsOnlyReturnsKeysThePrincipalCanRead(t *testing.T) {
	m, _ := makeDB()

	owner := auth.NewUser("team-payments-owner", nil)
	if _, err := postKeysHandler(m, owner, map[string]string{
		"id":   "stripe_prod_api_key",
		"data": "c2VjcmV0",
	}); err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	if _, err := postKeysHandler(m, owner, map[string]string{
		"id":   "internal_admin_jwt_secret",
		"data": "c2VjcmV0",
	}); err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	// A machine principal with zero ACL grants anywhere -- it was never added
	// to either key's ACL, and has no relationship to the owner. This models
	// the lowest-trust caller Knox can authenticate: any host that can present
	// a cert signed by Knox's CA.
	attacker := auth.NewMachine("unrelated-low-trust-host")

	// Confirm the attacker genuinely has no access to either key, the same way
	// getKeyHandler would enforce it.
	keyA, err := m.GetKey("stripe_prod_api_key", knox.Active)
	if err != nil {
		t.Fatal(err)
	}
	if attacker.CanAccess(keyA.ACL, knox.Read) {
		t.Fatal("test setup invalid: attacker should not have Read access")
	}

	result, apiErr := getKeysHandler(m, attacker, nil)
	if apiErr != nil {
		t.Fatalf("getKeysHandler returned an error: %+v", apiErr)
	}
	ids, ok := result.([]string)
	if !ok {
		t.Fatalf("unexpected response type %T", result)
	}
	if len(ids) != 0 {
		t.Fatalf("VULNERABLE: principal with zero ACL grants enumerated key IDs it cannot read: %v", ids)
	}

	// The owner, who does have access, must still see both keys.
	result, apiErr = getKeysHandler(m, owner, nil)
	if apiErr != nil {
		t.Fatalf("getKeysHandler returned an error: %+v", apiErr)
	}
	ownerIDs, ok := result.([]string)
	if !ok {
		t.Fatalf("unexpected response type %T", result)
	}
	found := map[string]bool{}
	for _, id := range ownerIDs {
		found[id] = true
	}
	if !found["stripe_prod_api_key"] || !found["internal_admin_jwt_secret"] {
		t.Fatalf("owner should see both of their own keys, got: %v", ownerIDs)
	}

	// A principal explicitly granted Read on only one of the two keys should
	// see exactly that one, not both.
	reader := auth.NewUser("payments-oncall-reader", nil)
	if err := m.UpdateAccess("stripe_prod_api_key", knox.Access{
		Type: knox.User, ID: reader.GetID(), AccessType: knox.Read,
	}); err != nil {
		t.Fatalf("failed to grant access: %v", err)
	}

	result, apiErr = getKeysHandler(m, reader, nil)
	if apiErr != nil {
		t.Fatalf("getKeysHandler returned an error: %+v", apiErr)
	}
	readerIDs, ok := result.([]string)
	if !ok {
		t.Fatalf("unexpected response type %T", result)
	}
	if len(readerIDs) != 1 || readerIDs[0] != "stripe_prod_api_key" {
		t.Fatalf("reader should see exactly the one key it was granted, got: %v", readerIDs)
	}
}
