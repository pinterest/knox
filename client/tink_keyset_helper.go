package client

import (
	"bytes"
	"encoding/json"
	"errors"
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

// Represents the info for a supported tink keyset template.
type tinkKeyTemplateInfo struct {
    knoxIDPrefix string
    templateFunc func() *tinkpb.KeyTemplate
}

// This map contains the supported tink key templates and the correcsponding naming rule for knox identifier
var tinkKeyTemplates = map[string] tinkKeyTemplateInfo{
	"TINK_AEAD_AES256_GCM": {"tink:aead:", aead.AES256GCMKeyTemplate},
	"TINK_AEAD_AES128_GCM": {"tink:aead:", aead.AES128GCMKeyTemplate},
	"TINK_MAC_HMAC_SHA512_256BITTAG": {"tink:mac:", mac.HMACSHA512Tag256KeyTemplate},
	"TINK_DSIG_ECDSA_P256": {"tink:dsig:", signature.ECDSAP256KeyTemplate},
	"TINK_DSIG_ED25519": {"tink:dsig:", signature.ED25519KeyTemplate},
	"TINK_HYBRID_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM": {"tink:hybrid:", hybrid.ECIESHKDFAES128GCMKeyTemplate},
	"TINK_DAEAD_AES256_SIV": {"tink:daead:", daead.AESSIVKeyTemplate},
	"TINK_SAEAD_AES128_GCM_HKDF_1MB": {"tink:saead:", streamingaead.AES128GCMHKDF1MBKeyTemplate},
	"TINK_SAEAD_AES128_GCM_HKDF_4KB": {"tink:saead:", streamingaead.AES128GCMHKDF4KBKeyTemplate},
}

// Returns the name of supported tink key templates in sorted order.
func nameOfSupportedTinkKeyTemplates() string {
	supportedTemplates := make([]string, 0, len(tinkKeyTemplates))
	for key := range tinkKeyTemplates {
		supportedTemplates = append(supportedTemplates, key)
	}
	sort.Strings(supportedTemplates)
	return strings.Join(supportedTemplates, "\n")
}

// <key_identifier> for tink keyset must start with "tink:<tink_primitive_short_name>:"
func checkTemplateNameAndKnoxIDForTinkKeyset(templateName string, knoxIentifier string) error {
	templateInfo, existed := tinkKeyTemplates[templateName]
	if !existed {
		return errors.New("not supported keyset template. See 'knox key-templates'")
	} else if !strings.HasPrefix(knoxIentifier, templateInfo.knoxIDPrefix) {
		return errors.New("<key_identifier> must have prefix '" + templateInfo.knoxIDPrefix + "'")
	}
	return nil
}

// Create a new tink keyset contains a single fresh key from the given tink key templateFunc.
func createNewTinkKeyset(templateFunc func() *tinkpb.KeyTemplate) []byte {
	// Creates a keyset handle that contains a single fresh key
	keysetHandle, err := keyset.NewHandle(templateFunc())
	if keysetHandle == nil || err != nil {
		fatalf("cannot get tink keyset handle: %v", err)
	}
	return convertTinkKeysetHandleToBytes(keysetHandle)
}

// Extract keyset from tink keyset handle and convert it to bytes
func convertTinkKeysetHandleToBytes(keysetHandle *keyset.Handle) []byte {
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	// To write cleartext keyset handle, must use package "insecurecleartextkeyset"
	if err := insecurecleartextkeyset.Write(keysetHandle, writer); err != nil {
		fatalf("cannot write tink keyset: %v", err)
	}
	return bytesBuffer.Bytes()
}

// Given a knox version list and a tink key templateFunc, create a new tink keyset contains a single fresh
// key from the given tink key templateFunc. Most importantly, the ID of this signle fresh key is different
// from the ID of all existed tink keys in the given knox this version list.
func addNewTinkKeyset(templateFunc func() *tinkpb.KeyTemplate, knoxVersionList knox.KeyVersionList) []byte {
	existedTinkKeysID := make(map[uint32]struct{})
	for _, v := range knoxVersionList {
		tinkKeyset := readTinkKeysetFromBytes(v.Data)
		existedTinkKeysID[tinkKeyset.PrimaryKeyId] = struct{}{}
	}
	var keysetHandle *keyset.Handle
	var err error
	for {
		keysetHandle, err = keyset.NewHandle(templateFunc())
		if keysetHandle == nil || err != nil {
			fatalf("cannot get tink keyset handle: %v", err)
		}
		newTinkKeyID := keysetHandle.KeysetInfo().PrimaryKeyId
		// Check whether the ID of created tink key is already existed
		if _, existed := existedTinkKeysID[newTinkKeyID]; !existed {
			break
		}
	}
	return convertTinkKeysetHandleToBytes(keysetHandle)
}

// Extract tink keyset from bytes.
func readTinkKeysetFromBytes(data []byte) *tinkpb.Keyset {
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(data)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		fatalf("unexpected error reading tink keyset: %v", err)
	}
	return tinkKeyset
}

// Given a knox version list, returns a tink keyset handle that has all tink keys in this knox version list
// and a map that map tink key IDs to knox version IDs. Since each version is a tink keyset that contains a
// single key, this func will enumerate all versions in the given version list and do the appending.
func getTinkKeysetHandleFromKnoxVersionList(
	knoxVersionList knox.KeyVersionList,
) (*keyset.Handle, map[uint32]uint64) {
	tinkKeyset := new(tinkpb.Keyset)
	tinkKeyIDToKnoxVersionID := make(map[uint32]uint64)
	for _, v := range knoxVersionList {
		keysetContainsASingleKey := readTinkKeysetFromBytes(v.Data)
		// the data of each version is a tink keyset that contains a single tink key
		singleKey := keysetContainsASingleKey.Key[0]
		if v.Status == knox.Primary {
			tinkKeyset.PrimaryKeyId = singleKey.KeyId
		}
		tinkKeyset.Key = append(tinkKeyset.Key, singleKey)
		tinkKeyIDToKnoxVersionID[singleKey.KeyId] = v.ID
	}
	// Convert tink keyset to tink keyset handle. tink doesn't allow transferring cleartext keyset to keyset
	// handle driectly. Hence, keyset is converted to bytes, then read by package insecurecleartextkeyset
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	writer.Write(tinkKeyset)
	reader := keyset.NewBinaryReader(bytesBuffer)
	keysetHandle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		fatalf("cannot get tink keyset handle: %v", err)
	}
	return keysetHandle, tinkKeyIDToKnoxVersionID
}

// Returns a string representation of the info of given tink keyset handle, which does not contain any 
// sensitive key material.
func getKeysetInfoFromTinkKeysetHandle(
	keysetHandle *keyset.Handle, 
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) string {
	// translate the info from the tink build-in function to json format
	keysetInfo := newJSONTinkKeysetInfo(keysetHandle.KeysetInfo(), tinkKeyIDToKnoxVersionID)
	keysetInfoForPrint, err := json.MarshalIndent(keysetInfo, "", "  ")
	if err != nil {
		fatalf(err.Error())
	}
	return string(keysetInfoForPrint)
}

// A strcut for translating tink keyset info to JSON format, doesn't contain any actual key material.
type JSONTinkKeysetInfo struct {
	PrimaryKeyId uint32 `json:"primary_key_id"`
	KeyInfo              []*JSONTinkKeysetInfo_KeyInfo `json:"key_info"`
}

// A strcut for translating tink key info to JSON format, doesn't contain any actual key material.
type JSONTinkKeysetInfo_KeyInfo struct {
	TypeUrl string `json:"type_url"`
	Status string `json:"status"`
	KeyId uint32 `json:"key_id"`
	OutputPrefixType string `json:"output_prefix_type"`
	KnoxVersionID uint64 `json:"knox_version_id"`
}

// Helper to translate tink keyset info to JSON format
func newJSONTinkKeysetInfo(
	keysetInfo *tinkpb.KeysetInfo,
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) JSONTinkKeysetInfo {
	return JSONTinkKeysetInfo{
	  keysetInfo.PrimaryKeyId,
	  newJSONTinkKeysetInfo_KeyInfo(keysetInfo.KeyInfo, tinkKeyIDToKnoxVersionID),
	}
}

// Helper to translate tink keys info to JSON format
func newJSONTinkKeysetInfo_KeyInfo(
	keyseInfo_KeyInfo []*tinkpb.KeysetInfo_KeyInfo,
	tinkKeyIDToKnoxVersionID map[uint32]uint64,
) []*JSONTinkKeysetInfo_KeyInfo {
	var tinkKeyInfo []*JSONTinkKeysetInfo_KeyInfo
	for _, v := range keyseInfo_KeyInfo {
		tinkKeyInfo = append(tinkKeyInfo, &JSONTinkKeysetInfo_KeyInfo{
			v.TypeUrl,
			v.Status.String(),
			v.KeyId,
			v.OutputPrefixType.String(),
			tinkKeyIDToKnoxVersionID[v.KeyId],
		})
	}
	return tinkKeyInfo
}
