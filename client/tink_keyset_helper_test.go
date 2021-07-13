package client

import (
	"sort"
	"strings"
	"testing"
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
