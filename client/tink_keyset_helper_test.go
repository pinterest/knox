package client

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
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

func TestCheckTemplateNameAndKnoxIDForTinkKeyset(t *testing.T) {
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("invalid", "invalid"); err == nil {
		t.Fatalf("cannot check whether knox identifier for tink keyset obey the naming rule")
	}
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("TINK_AEAD_AES256_GCM", "invalid"); err == nil {
		t.Fatalf("cannot check whether knox identifier for tink keyset obey the naming rule")
	}
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("TINK_AEAD_AES256_GCM", "tink:dsig:"); err == nil {
		t.Fatalf("cannot check whether knox identifier for tink keyset obey the naming rule")
	}
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("TINK_AEAD_AES256_GCM", "tink:aead:"); err != nil {
		t.Fatalf("cannot check whether knox identifier for tink keyset obey the naming rule")
	}
}

func TestCreateNewTinkKeyset(t *testing.T) {
	keyTemplate := mac.HMACSHA512Tag256KeyTemplate
	keysetInBytes := createNewTinkKeyset(keyTemplate)
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(keysetInBytes)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		t.Fatalf("unexpected error reading tink keyset data: %v", err)
	}
	if len(tinkKeyset.Key) != 1 {
		t.Fatalf("incorrect number of keys in the keyset: %d", len(tinkKeyset.Key))
	}
	tinkKey := tinkKeyset.Key[0]
	if tinkKeyset.PrimaryKeyId != tinkKey.KeyId {
		t.Fatalf("incorrect primary key id, expect %d, got %d", tinkKey.KeyId, tinkKeyset.PrimaryKeyId)
	}
	if tinkKey.KeyData.TypeUrl != keyTemplate().TypeUrl {
		t.Fatalf("incorrect type url, expect %s, got %s", keyTemplate().TypeUrl, tinkKey.KeyData.TypeUrl)
	}
	keysetHandle, err := testkeyset.NewHandle(tinkKeyset)
	if err != nil {
		t.Fatalf("unexpected error creating new KeysetHandle: %v", err)
	}
	if _, err = mac.New(keysetHandle); err != nil {
		t.Fatalf("cannot get primitive from generated keyset: %s", err)
	}
}

func TestConvertTinkKeysetHandleToBytes(t *testing.T) {
	keyTemplate := mac.HMACSHA256Tag128KeyTemplate()
	keysetHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	keysetInBytes := convertTinkKeysetHandleToBytes(keysetHandle)
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(keysetInBytes)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		t.Fatalf("unexpected error reading tink keyset data: %v", err)
	}
	if err := keyset.Validate(tinkKeyset); err != nil {
		t.Fatalf("cannot extract keyset from keyset handle and convert it to bytes")
	}
}
