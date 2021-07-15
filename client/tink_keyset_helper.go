package client

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/streamingaead"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// tinkKeyTemplateInfo represents the info for a supported tink keyset template.
type tinkKeyTemplateInfo struct {
	knoxIDPrefix string
	templateFunc func() *tinkpb.KeyTemplate
}

// tinkKeyTemplates contains the supported tink key templates and the correcsponding naming rule for knox identifier
var tinkKeyTemplates = map[string]tinkKeyTemplateInfo{
	"TINK_AEAD_AES256_GCM":                               {"tink:aead:", aead.AES256GCMKeyTemplate},
	"TINK_AEAD_AES128_GCM":                               {"tink:aead:", aead.AES128GCMKeyTemplate},
	"TINK_MAC_HMAC_SHA512_256BITTAG":                     {"tink:mac:", mac.HMACSHA512Tag256KeyTemplate},
	"TINK_DSIG_ECDSA_P256":                               {"tink:dsig:", signature.ECDSAP256KeyTemplate},
	"TINK_DSIG_ED25519":                                  {"tink:dsig:", signature.ED25519KeyTemplate},
	"TINK_HYBRID_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM": {"tink:hybrid:", hybrid.ECIESHKDFAES128GCMKeyTemplate},
	"TINK_DAEAD_AES256_SIV":                              {"tink:daead:", daead.AESSIVKeyTemplate},
	"TINK_SAEAD_AES128_GCM_HKDF_1MB":                     {"tink:saead:", streamingaead.AES128GCMHKDF1MBKeyTemplate},
	"TINK_SAEAD_AES128_GCM_HKDF_4KB":                     {"tink:saead:", streamingaead.AES128GCMHKDF4KBKeyTemplate},
}

// nameOfSupportedTinkKeyTemplates returns the name of supported tink key templates in sorted order.
func nameOfSupportedTinkKeyTemplates() string {
	supportedTemplates := make([]string, 0, len(tinkKeyTemplates))
	for key := range tinkKeyTemplates {
		supportedTemplates = append(supportedTemplates, key)
	}
	sort.Strings(supportedTemplates)
	return strings.Join(supportedTemplates, "\n")
}

// checkTemplateNameAndKnoxIDForTinkKeyset checks whether knox identifier start with "tink:<tink_primitive_short_name>:".
func checkTemplateNameAndKnoxIDForTinkKeyset(templateName string, knoxIentifier string) error {
	templateInfo, ok := tinkKeyTemplates[templateName]
	if !ok {
		return errors.New("not supported Tink key template. See 'knox key-templates'")
	} else if !strings.HasPrefix(knoxIentifier, templateInfo.knoxIDPrefix) {
		errInfo := fmt.Sprintf("<key_identifier> must have prefix '%s'", templateInfo.knoxIDPrefix)
		return errors.New(errInfo)
	}
	return nil
}

// createNewTinkKeyset creates a new tink keyset contains a single fresh key from the given tink key templateFunc.
func createNewTinkKeyset(templateFunc func() *tinkpb.KeyTemplate) []byte {
	// Creates a keyset handle that contains a single fresh key
	keysetHandle, err := keyset.NewHandle(templateFunc())
	if keysetHandle == nil || err != nil {
		fatalf("cannot get tink keyset handle: %v", err)
	}
	return convertTinkKeysetHandleToBytes(keysetHandle)
}

// convertTinkKeysetHandleToBytes extracts keyset from tink keyset handle and converts it to bytes
func convertTinkKeysetHandleToBytes(keysetHandle *keyset.Handle) []byte {
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	// To write cleartext keyset handle, must use package "insecurecleartextkeyset"
	err := insecurecleartextkeyset.Write(keysetHandle, writer)
	if err != nil {
		fatalf("cannot write tink keyset: %v", err)
	}
	return bytesBuffer.Bytes()
}
