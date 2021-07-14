package client

import (
	"strings"
	"testing"
)

func TestNameOfSupportedTinkKeyTemplates(t *testing.T) {
	names := []string{
		"TINK_AEAD_AES128_GCM",
		"TINK_AEAD_AES256_GCM",
		"TINK_DAEAD_AES256_SIV",
		"TINK_DSIG_ECDSA_P256",
		"TINK_DSIG_ED25519",
		"TINK_HYBRID_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
		"TINK_MAC_HMAC_SHA512_256BITTAG",
		"TINK_SAEAD_AES128_GCM_HKDF_1MB",
		"TINK_SAEAD_AES128_GCM_HKDF_4KB",
	}
	expected := strings.Join(names, "\n")
	if expected != nameOfSupportedTinkKeyTemplates() {
		t.Fatalf("cannot list name of supported tink key templates correctly")
	}
}
