package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	"github.com/pinterest/knox"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
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

func TestObeyNamingRule(t *testing.T) {
	if err := obeyNamingRule("invalid", "invalid"); err == nil {
		t.Fatalf("cannot identify invalid tink key template")
	}
	for k := range tinkKeyTemplates {
		illegalKnoxIdentifier := "wrongKnoxIdentifier"
		err := obeyNamingRule(k, illegalKnoxIdentifier)
		if err == nil {
			t.Fatalf("cannot identify illegal knox identifer for template '%s'", k)
		}
	}
	for k, v := range tinkKeyTemplates {
		legalKnoxIdentifier := v.knoxIDPrefix + "test"
		err := obeyNamingRule(k, legalKnoxIdentifier)
		if err != nil {
			t.Fatalf("cannot accept legal knox identifer for template '%s'", k)
		}
	}
}

func TestIsIDforTinkKeyset(t *testing.T) {
	if isIDforTinkKeyset("invalid") {
		t.Fatalf("cannot identify knox identifier that is not for tink keyset")
	}
	for _, templateInfo := range tinkKeyTemplates {
		knoxIdentifierForTinkKeyset := templateInfo.knoxIDPrefix + "test"
		if !isIDforTinkKeyset(knoxIdentifierForTinkKeyset) {
			t.Fatalf("cannot identify knox identifier that is for tink keyset")
		}
	}
}

func TestCreateNewTinkKeyset(t *testing.T) {
	keyTemplate := mac.HMACSHA512Tag256KeyTemplate
	keysetInBytes, err := createNewTinkKeyset(keyTemplate)
	if err != nil {
		t.Fatalf("cannot create a new tink keyset: %v", err)
	}
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
	keysetInBytes, err := convertTinkKeysetHandleToBytes(keysetHandle)
	if err != nil {
		t.Fatalf("cannot create convert tink keyset handle to bytes: %v", err)
	}
	bytesBuffer := new(bytes.Buffer)
	bytesBuffer.Write(keysetInBytes)
	tinkKeyset, err := keyset.NewBinaryReader(bytesBuffer).Read()
	if err != nil {
		t.Fatalf("unexpected error reading tink keyset data: %v", err)
	}
	if err := keyset.Validate(tinkKeyset); err != nil {
		t.Fatalf("when convert tink keyset handle to bytes, the keyset becomes invalid")
	}
}

// getDummyKnoxVersionList is a helper for test. It returns a dummy knox version list for testing and a map from
// Tink key ID to knox version ID. The data of each version is a Tink keyset in bytes that contains a single Tink
// key. Argument counts decides how many versions are in this dummy veriosn list. Argument templateFunc decides
// the type of created Tink keyset in each version.
func getDummyKnoxVersionList(
	counts int,
	templateFunc func() *tinkpb.KeyTemplate,
) (knox.KeyVersionList, map[uint32]uint64) {
	var dummyVersionList knox.KeyVersionList
	tinkKeyIDToKnoxVersionID := make(map[uint32]uint64)
	// counts decide how many versions this dummy version list will have
	for i := 0; i < counts; i++ {
		// get a tink keyset handle that contains a fresh single key and the keyID is not duplicated
		var keysetHandle *keyset.Handle
		var err error
		isDuplicated := true
		for isDuplicated {
			keysetHandle, err = keyset.NewHandle(templateFunc())
			if keysetHandle == nil || err != nil {
				fatalf("cannot get tink keyset handle: %v", err)
			}
			_, isDuplicated = tinkKeyIDToKnoxVersionID[keysetHandle.KeysetInfo().PrimaryKeyId]
		}
		// Convert keyset handle to bytes, since the data in each version is bytes
		var keysetInBytes []byte
		keysetInBytes, err = convertTinkKeysetHandleToBytes(keysetHandle)
		if err != nil {
			fatalf(err.Error())
		}
		// Add a new version to the dummy version list. Only one Primary version, all others are Active version.
		var status knox.VersionStatus
		if i == 0 {
			status = knox.Primary
		} else {
			status = knox.Active
		}
		// To be noticed, index i is used as dummy knox version ID and dummy creation time.
		dummyVersionList = append(dummyVersionList, knox.KeyVersion{
			ID:           uint64(i),
			Data:         keysetInBytes,
			Status:       status,
			CreationTime: int64(i),
		})
		tinkKeyIDToKnoxVersionID[keysetHandle.KeysetInfo().PrimaryKeyId] = uint64(i)
	}
	return dummyVersionList, tinkKeyIDToKnoxVersionID
}

func TestAddNewTinkKeyset(t *testing.T) {
	keyTemplate := aead.AES256GCMKeyTemplate
	// create a dummy version list has one million Tink keys, this large number of Tink keys is used to
	// check whether func addNewTinkKeyset will add duplicated Key
	dummyVersionList, tinkKeyIDToKnoxVersionID := getDummyKnoxVersionList(1000000, keyTemplate)
	newKeysetInBytes, err := addNewTinkKeyset(keyTemplate, dummyVersionList)
	if err != nil {
		t.Fatalf("cannot add new Tink keyset: %v", err)
	}
	// convert bytes to a Tink keyset, and check whether it is a valid keyset
	tinkKeyset, err := readTinkKeysetFromBytes(newKeysetInBytes)
	if err != nil {
		t.Fatalf("unexpected error reading tink keyset data: %v", err)
	}
	if len(tinkKeyset.Key) != 1 {
		t.Fatalf("incorrect number of keys in the keyset: %d", len(tinkKeyset.Key))
	}
	tinkKey := tinkKeyset.Key[0]
	_, isDuplicated := tinkKeyIDToKnoxVersionID[tinkKey.KeyId]
	if isDuplicated {
		t.Fatalf("the ID of new Tink key is duplicated")
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
	err = insecurecleartextkeyset.Write(keysetHandle, writer)
	if err != nil {
		t.Fatalf("unexpected error writing tink keyset handle")
	}
	tinkKeyset, err := readTinkKeysetFromBytes(bytesBuffer.Bytes())
	if err != nil {
		t.Fatalf("cannot read tink keyset from bytes")
	}
	err = keyset.Validate(tinkKeyset)
	if err != nil {
		t.Fatalf("the result of readTinkKeysetFromBytes is not a valid Tink keyset")
	}
}

func TestGetTinkKeysetHandleFromKnoxVersionList(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	dummyVersionList, tinkKeyIDtoKnoxVersionID := getDummyKnoxVersionList(1000, keyTemplate)
	keysetHandle, mapping, err := getTinkKeysetHandleFromKnoxVersionList(dummyVersionList)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if _, err := aead.New(keysetHandle); err != nil {
		t.Fatalf("cannot get primitive from generated keyset handle: %s", err)
	}
	for k, v := range tinkKeyIDtoKnoxVersionID {
		if v != mapping[k] {
			t.Fatalf("cannot map tink key id to knox version id correctly")
		}
	}
}

func TestConvertCleartextTinkKeysetToHandle(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	keyTemplate := mac.HMACSHA256Tag128KeyTemplate()
	keysetHandle, err := keyset.NewHandle(keyTemplate)
	if keysetHandle == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}
	tinkKeyset := insecurecleartextkeyset.KeysetMaterial(keysetHandle)
	parsedHandle, err := convertCleartextTinkKeysetToHandle(tinkKeyset)
	if err != nil {
		t.Fatalf("unexpected error reading keyset: %v", err)
	}
	parsedKeyset := insecurecleartextkeyset.KeysetMaterial(parsedHandle)
	if !proto.Equal(tinkKeyset, parsedKeyset) {
		t.Fatalf("parsed keyset (%s) doesn't match original keyset (%s)", parsedKeyset, tinkKeyset)
	}
}

func TestGetKeysetInfoFromTinkKeysetHandle(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// 100 is the dummy knox version id
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 100}
	var keysInfo []*tinkKeyInfo
	rawKeysetInfo := keysetHandle.KeysetInfo()
	keysInfo = append(keysInfo, &tinkKeyInfo{
		rawKeysetInfo.KeyInfo[0].TypeUrl,
		rawKeysetInfo.KeyInfo[0].Status.String(),
		rawKeysetInfo.KeyInfo[0].KeyId,
		rawKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		100,
	})
	keysetInfo := tinkKeysetInfo{
		rawKeysetInfo.PrimaryKeyId,
		keysInfo,
	}
	keysetInfoForPrint, err := json.MarshalIndent(keysetInfo, "", "  ")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := string(keysetInfoForPrint)
	got, err := getKeysetInfoFromTinkKeysetHandle(keysetHandle, tinkKeyIDToKnoxVersionID)
	if err != nil || expected != got {
		t.Fatalf("cannot get keyset info in json format")
	}
}

func TestNewTinkKeysetInfo(t *testing.T) {
	keyTemplate := aead.AES128GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// 123456 is the dummy knox version id
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 123456}
	var keysInfo []*tinkKeyInfo
	rawKeysetInfo := keysetHandle.KeysetInfo()
	keysInfo = append(keysInfo, &tinkKeyInfo{
		rawKeysetInfo.KeyInfo[0].TypeUrl,
		rawKeysetInfo.KeyInfo[0].Status.String(),
		rawKeysetInfo.KeyInfo[0].KeyId,
		rawKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		123456,
	})
	expected, _ := json.Marshal(tinkKeysetInfo{
		rawKeysetInfo.PrimaryKeyId,
		keysInfo,
	})
	got, _ := json.Marshal(newTinkKeysetInfo(keysetHandle.KeysetInfo(), tinkKeyIDToKnoxVersionID))
	if string(got) != string(expected) {
		t.Fatalf("cannot create JSONTinkKeysetInfo correctly")
	}
}

func TestNewTinkKeysInfo(t *testing.T) {
	keyTemplate := aead.AES256GCMKeyTemplate
	keysetHandle, err := keyset.NewHandle(keyTemplate())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// 1234567890 is the dummy knox version id
	tinkKeyIDToKnoxVersionID := map[uint32]uint64{keysetHandle.KeysetInfo().PrimaryKeyId: 1234567890}
	var keysInfo []*tinkKeyInfo
	rawKeysetInfo := keysetHandle.KeysetInfo()
	keysInfo = append(keysInfo, &tinkKeyInfo{
		rawKeysetInfo.KeyInfo[0].TypeUrl,
		rawKeysetInfo.KeyInfo[0].Status.String(),
		rawKeysetInfo.KeyInfo[0].KeyId,
		rawKeysetInfo.KeyInfo[0].OutputPrefixType.String(),
		1234567890,
	})
	expected, _ := json.Marshal(keysInfo)
	got, _ := json.Marshal(newTinkKeysInfo(keysetHandle.KeysetInfo().KeyInfo, tinkKeyIDToKnoxVersionID))
	if string(got) != string(expected) {
		t.Fatalf("cannot create JSONTinkKeysetInfo_KeyInfo correctly")
	}
}
