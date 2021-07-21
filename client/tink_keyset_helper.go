package client

import (
	"bytes"
	"encoding/json"
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
	"github.com/pinterest/knox"

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

// obeyNamingRule checks whether knox identifier start with "tink:<tink_primitive_short_name>:".
func obeyNamingRule(templateName string, knoxIentifier string) error {
	templateInfo, ok := tinkKeyTemplates[templateName]
	if !ok {
		return errors.New("not supported Tink key template. See 'knox key-templates'")
	} else if !strings.HasPrefix(knoxIentifier, templateInfo.knoxIDPrefix) {
		return fmt.Errorf("<key_identifier> must have prefix '%s'", templateInfo.knoxIDPrefix)
	}
	return nil
}

// isIDforTinkKeyset checks whether knox identifier start with "tink:<tink_primitive_short_name>:".
func isIDforTinkKeyset(knoxIdentifier string) bool {
	for _, templateInfo := range tinkKeyTemplates {
		if strings.HasPrefix(knoxIdentifier, templateInfo.knoxIDPrefix) {
			return true
		}
	}
	return false
}

// createNewTinkKeyset creates a new tink keyset contains a single fresh key from the given tink key templateFunc.
func createNewTinkKeyset(templateFunc func() *tinkpb.KeyTemplate) ([]byte, error) {
	// Creates a keyset handle that contains a single fresh key
	keysetHandle, err := keyset.NewHandle(templateFunc())
	if keysetHandle == nil || err != nil {
		return nil, fmt.Errorf("cannot get tink keyset handle: %v", err)
	}
	return convertTinkKeysetHandleToBytes(keysetHandle)
}

// convertTinkKeysetHandleToBytes extracts keyset from tink keyset handle and converts it to bytes
func convertTinkKeysetHandleToBytes(keysetHandle *keyset.Handle) ([]byte, error) {
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	// To write cleartext keyset handle, must use package "insecurecleartextkeyset"
	err := insecurecleartextkeyset.Write(keysetHandle, writer)
	if err != nil {
		return nil, fmt.Errorf("cannot write tink keyset: %v", err)
	}
	return bytesBuffer.Bytes(), nil
}

// addNewTinkKeyset receives a knox version list and a tink key templateFunc, create a new tink keyset contains
// a single fresh key from the given tink key templateFunc. Most importantly, the ID of this single fresh key is
// different from the ID of all existing tink keys in the given knox version list (avoid Tink key ID duplications).
func addNewTinkKeyset(templateFunc func() *tinkpb.KeyTemplate, knoxVersionList knox.KeyVersionList) ([]byte, error) {
	existingTinkKeysID := make(map[uint32]struct{})
	for _, v := range knoxVersionList {
		tinkKeysetForAVersion, err := readTinkKeysetFromBytes(v.Data)
		if err != nil {
			return nil, err
		}
		existingTinkKeysID[tinkKeysetForAVersion.PrimaryKeyId] = struct{}{}
	}
	var keysetHandle *keyset.Handle
	var err error
	// This loop is for retrying until a non-duplicate key id is generated.
	isDuplicated := true
	for isDuplicated {
		keysetHandle, err = keyset.NewHandle(templateFunc())
		if keysetHandle == nil || err != nil {
			return nil, fmt.Errorf("cannot get tink keyset handle: %v", err)
		}
		newTinkKeyID := keysetHandle.KeysetInfo().PrimaryKeyId
		_, isDuplicated = existingTinkKeysID[newTinkKeyID]
	}
	return convertTinkKeysetHandleToBytes(keysetHandle)
}

// readTinkKeysetFromBytes extracts tink keyset from bytes.
func readTinkKeysetFromBytes(data []byte) (*tinkpb.Keyset, error) {
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(data)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		return nil, fmt.Errorf("unexpected error reading tink keyset: %v", err)
	}
	return tinkKeyset, nil
}

// getTinkKeysetHandleFromKnoxVersionList returns a tink keyset handle that has all tink keys in the
// received knox version list and a map from tink key IDs to knox version IDs. To be noticed, each
// knox version contains a tink keyset that has a single tink key (tink key has a property, tink key id).
// This func enumerates the given knox version list, put tink keys from different knox versions into
// one tink keyset "tinkKeysetHasAllKeys". Also, this func records which tink key is from which knox
// version in a map "tinkKeyIDToKnoxVersionID".
func getTinkKeysetHandleFromKnoxVersionList(
	knoxVersionList knox.KeyVersionList,
) (*keyset.Handle, map[uint32]uint64, error) {
	tinkKeysetHasAllKeys := new(tinkpb.Keyset)
	tinkKeyIDToKnoxVersionID := make(map[uint32]uint64)
	for _, v := range knoxVersionList {
		// the data of each version is a tink keyset that contains a single tink key
		keyComponent, err := readTinkKeysetFromBytes(v.Data)
		if err != nil {
			return nil, nil, err
		}
		singleKey := keyComponent.Key[0]
		if v.Status == knox.Primary {
			tinkKeysetHasAllKeys.PrimaryKeyId = singleKey.KeyId
		}
		tinkKeysetHasAllKeys.Key = append(tinkKeysetHasAllKeys.Key, singleKey)
		tinkKeyIDToKnoxVersionID[singleKey.KeyId] = v.ID
	}
	keysetHandle, err := convertCleartextTinkKeysetToHandle(tinkKeysetHasAllKeys)
	if err != nil {
		return nil, nil, err
	}
	return keysetHandle, tinkKeyIDToKnoxVersionID, nil
}

// convertCleartextTinkKeysetToHandle converts cleartext tink keyset to tink keyset handle
func convertCleartextTinkKeysetToHandle(cleartextTinkKeyset *tinkpb.Keyset) (*keyset.Handle, error) {
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	writer.Write(cleartextTinkKeyset)
	reader := keyset.NewBinaryReader(bytesBuffer)
	// To get keyset handle from cleartext keyset, must use package "insecurecleartextkeyset"
	keysetHandle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("cannot get tink keyset handle: %v", err)
	}
	return keysetHandle, nil
}

// getKeysetInfoFromTinkKeysetHandle returns a string representation of the info of the given tink keyset
// handle. The returned string which does not contain any sensitive key material.
func getKeysetInfoFromTinkKeysetHandle(
	keysetHandle *keyset.Handle,
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) (string, error) {
	// translate the info from the tink build-in function to json format
	keysetInfo := NewTinkKeysetInfo(keysetHandle.KeysetInfo(), tinkKeyIDToKnoxVersionID)
	keysetInfoForPrint, err := json.MarshalIndent(keysetInfo, "", "  ")
	if err != nil {
		return "", err
	}
	return string(keysetInfoForPrint), nil
}

// TinkKeysetInfo translates tink keyset info to JSON format, doesn't contain any actual key material.
type TinkKeysetInfo struct {
	PrimaryKeyId uint32         `json:"primary_key_id"`
	KeyInfo      []*TinkKeyInfo `json:"key_info"`
}

// TinkKeyInfo translates tink key info to JSON format, doesn't contain any actual key material.
type TinkKeyInfo struct {
	TypeUrl          string `json:"type_url"`
	Status           string `json:"status"`
	KeyId            uint32 `json:"key_id"`
	OutputPrefixType string `json:"output_prefix_type"`
	KnoxVersionID    uint64 `json:"knox_version_id"`
}

// NewTinkKeysetInfo translates Tink keyset info to JSON format.
func NewTinkKeysetInfo(
	keysetInfo *tinkpb.KeysetInfo,
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) TinkKeysetInfo {
	return TinkKeysetInfo{
		keysetInfo.PrimaryKeyId,
		NewTinkKeysInfo(keysetInfo.KeyInfo, tinkKeyIDToKnoxVersionID),
	}
}

// NewTinkKeyInfo translates Tink key info to JSON format.
func NewTinkKeysInfo(
	keyseInfo_KeyInfo []*tinkpb.KeysetInfo_KeyInfo,
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) []*TinkKeyInfo {
	var tinkKeysInfo []*TinkKeyInfo
	for _, v := range keyseInfo_KeyInfo {
		tinkKeysInfo = append(tinkKeysInfo, &TinkKeyInfo{
			v.TypeUrl,
			v.Status.String(),
			v.KeyId,
			v.OutputPrefixType.String(),
			tinkKeyIDToKnoxVersionID[v.KeyId],
		})
	}
	return tinkKeysInfo
}
