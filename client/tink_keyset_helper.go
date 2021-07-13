package client

import (
	"sort"
	"strings"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/streamingaead"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Represents the info for a supported tink keyset template.
type tinkKeyTemplateInfo struct {
	knoxIDPrefix string
	templateFunc func() *tinkpb.KeyTemplate
}

// This map contains the supported tink key templates and the correcsponding naming rule for knox identifier
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

// Returns the name of supported tink key templates in sorted order.
func nameOfSupportedTinkKeyTemplates() string {
	supportedTemplates := make([]string, 0, len(tinkKeyTemplates))
	for key := range tinkKeyTemplates {
		supportedTemplates = append(supportedTemplates, key)
	}
	sort.Strings(supportedTemplates)
	return strings.Join(supportedTemplates, "\n")
}
