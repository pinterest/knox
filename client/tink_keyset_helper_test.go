package client

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	"github.com/pinterest/knox"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNameOfSupportedTinkKeyTemplates(t *testing.T) {
	supportedTemplates := make([]string, 0, len(tinkKeyTemplates))
	for key := range tinkKeyTemplates {
		supportedTemplates = append(supportedTemplates, key)
	}
	sort.Strings(supportedTemplates)
	strings.Join(supportedTemplates, "\n")
	expected := strings.Join(supportedTemplates, "\n")
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
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("TINK_AEAD_AES256_GCM", "tink:aead:"); err != nil {
		t.Fatalf("cannot check whether knox identifier for tink keyset obey the naming rule")
	}
	if err := checkTemplateNameAndKnoxIDForTinkKeyset("TINK_AEAD_AES256_GCM", "tink:dsig:"); err == nil {
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

// Helper. Build a dummy knox version list for testing.
func getDummyKnoxVersionList(
	counts int, 
	templateFunc func() *tinkpb.KeyTemplate,
) (knox.KeyVersionList, map[uint32]uint64) {
	var dummyVersionList knox.KeyVersionList
	tinkKeyIDToKnoxVersionID := make(map[uint32]uint64)
	// counts decide how many versions this dummy version list will have
	for i := 0; i < counts; i++ {
		// get a tink keyset in bytes that contains a fresh single key and the keyID is not duplicated
		var keysetInbytes []byte
		for{
			keysetHandle, err := keyset.NewHandle(templateFunc())
			if keysetHandle == nil || err != nil {
				fatalf("cannot get tink keyset handle: %v", err)
			}
			if _, existed := tinkKeyIDToKnoxVersionID[keysetHandle.KeysetInfo().PrimaryKeyId]; !existed {
				tinkKeyIDToKnoxVersionID[keysetHandle.KeysetInfo().PrimaryKeyId] = uint64(i)
				bytesBuffer := new(bytes.Buffer)
				writer := keyset.NewBinaryWriter(bytesBuffer)
				if err := insecurecleartextkeyset.Write(keysetHandle, writer); err != nil {
					fatalf("cannot write tink keyset: %v", err)
				}
				keysetInbytes = bytesBuffer.Bytes()
				break
			}
		}
		// Add a new version to dummy version list
		var status knox.VersionStatus
		if i == 0 {
			status = knox.Primary
		} else {
			status = knox.Active
		}
		dummyVersionList = append(dummyVersionList, knox.KeyVersion{
			ID: uint64(i),
			Data: keysetInbytes,
			Status: status,
			CreationTime: int64(i),
		})
	}
	return dummyVersionList, tinkKeyIDToKnoxVersionID

}

func TestAddNewTinkKeyset(t *testing.T) {
	keyTemplate := aead.AES256GCMKeyTemplate
	dummyVersionList, tinkKeyIDToKnoxVersionID := getDummyKnoxVersionList(100000, keyTemplate)
	newKeysetInBytes := addNewTinkKeyset(keyTemplate, dummyVersionList)
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(newKeysetInBytes)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		t.Fatalf("unexpected error reading tink keyset data: %v", err)
	}
	if len(tinkKeyset.Key) != 1 {
		t.Fatalf("incorrect number of keys in the keyset: %d", len(tinkKeyset.Key))
	}
	tinkKey := tinkKeyset.Key[0]
	if _, existed := tinkKeyIDToKnoxVersionID[tinkKey.KeyId]; existed {
		t.Fatalf("the ID of added new key is duplicated")
	}
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
	if _, err = aead.New(keysetHandle); err != nil {
		t.Fatalf("cannot get primitive from generated keyset: %s", err)
	}
}

func TestReadTinkKeysetFromBytes(t *testing.T) {
	keyTemplate := mac.HMACSHA256Tag128KeyTemplate()
	keysetHandle, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	bytesBuffer := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(bytesBuffer)
	if err = insecurecleartextkeyset.Write(keysetHandle, writer); err != nil {
		t.Fatalf("unexpected error writing tink keyset handle")
	}
	tinkKeyset := readTinkKeysetFromBytes(bytesBuffer.Bytes())
	if err := keyset.Validate(tinkKeyset); err != nil {
		t.Fatalf("cannot read tink keyset from bytes")
	}
}

func TestGetTinkKeysetHandleFromKnoxVersionList(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	dummyVersionList, tinkKeyIDtoKnoxVersionID := getDummyKnoxVersionList(1000, keyTemplate)
	keysetHandle, mapping := getTinkKeysetHandleFromKnoxVersionList(dummyVersionList)
	if _, err := aead.New(keysetHandle); err != nil {
		t.Fatalf("cannot get primitive from generated keyset handle: %s", err)
	}
	for k, v := range tinkKeyIDtoKnoxVersionID {
		if v != mapping[k] {
			t.Fatalf("cannot map tink key id to knox version id correctly")
		}
	}
}

func TestGetKeysetInfoFromTinkKeysetHandle(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 100}
	var tinkKeyInfo []*JSONTinkKeysetInfo_KeyInfo
	tinkKeysetInfo := keysetHandle.KeysetInfo()
	tinkKeyInfo = append(tinkKeyInfo, &JSONTinkKeysetInfo_KeyInfo{
		tinkKeysetInfo.KeyInfo[0].TypeUrl,
		tinkKeysetInfo.KeyInfo[0].Status.String(),
		tinkKeysetInfo.KeyInfo[0].KeyId,
		tinkKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		100, // dummy knox version id
	})
	keysetInfo := JSONTinkKeysetInfo{
		tinkKeysetInfo.PrimaryKeyId,
		tinkKeyInfo,
	}
	keysetInfoForPrint, err := json.MarshalIndent(keysetInfo, "", "  ")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := string(keysetInfoForPrint)
	got := getKeysetInfoFromTinkKeysetHandle(keysetHandle, tinkKeyIDToKnoxVersionID)
	if expected != got {
		t.Fatalf("cannot get keyset info in json format")
	}
}

func TestNewJSONTinkKeysetInfo(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 123456}
	var tinkKeyInfo []*JSONTinkKeysetInfo_KeyInfo
	tinkKeysetInfo := keysetHandle.KeysetInfo()
	tinkKeyInfo = append(tinkKeyInfo, &JSONTinkKeysetInfo_KeyInfo{
		tinkKeysetInfo.KeyInfo[0].TypeUrl,
		tinkKeysetInfo.KeyInfo[0].Status.String(),
		tinkKeysetInfo.KeyInfo[0].KeyId,
		tinkKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		123456,
	})
	expected, _ := json.Marshal(JSONTinkKeysetInfo{
		tinkKeysetInfo.PrimaryKeyId,
		tinkKeyInfo,
	})
	got, _ := json.Marshal(newJSONTinkKeysetInfo(keysetHandle.KeysetInfo(), tinkKeyIDToKnoxVersionID))
	if string(got) != string(expected) {
		t.Fatalf("cannot create JSONTinkKeysetInfo correctly")
	}
}

func TestNewJSONTinkKeysetInfo_KeyInfo(t *testing.T) {
	keyTemplate := aead.AES256GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 1234567890}
	var tinkKeyInfo []*JSONTinkKeysetInfo_KeyInfo
	tinkKeysetInfo := keysetHandle.KeysetInfo()
	tinkKeyInfo = append(tinkKeyInfo, &JSONTinkKeysetInfo_KeyInfo{
		tinkKeysetInfo.KeyInfo[0].TypeUrl,
		tinkKeysetInfo.KeyInfo[0].Status.String(),
		tinkKeysetInfo.KeyInfo[0].KeyId,
		tinkKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		1234567890,
	})
	expected, _ := json.Marshal(tinkKeyInfo)
	got, _ := json.Marshal(newJSONTinkKeysetInfo_KeyInfo(keysetHandle.KeysetInfo().KeyInfo, tinkKeyIDToKnoxVersionID))
	if string(got) != string(expected) {
		t.Fatalf("cannot create JSONTinkKeysetInfo_KeyInfo correctly")
	}
}
