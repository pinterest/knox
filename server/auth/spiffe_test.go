package auth

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
)

func sanExtension(t *testing.T, names ...asn1.RawValue) []pkix.Extension {
	t.Helper()
	seq, err := asn1.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{{Id: oidExtensionSubjectAltName, Value: seq}}
}

func TestGetURINamesFromExtensions(t *testing.T) {
	const spiffeID = "spiffe://example.com/service"
	dnsName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("host.example.com")}

	tests := []struct {
		name  string
		names []asn1.RawValue
		want  []string
	}{
		{
			name:  "context-specific URI",
			names: []asn1.RawValue{dnsName, {Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(spiffeID)}},
			want:  []string{spiffeID},
		},
		{
			name:  "universal tag 6",
			names: []asn1.RawValue{dnsName, {Class: asn1.ClassUniversal, Tag: 6, Bytes: []byte(spiffeID)}},
		},
		{
			name:  "application tag 6",
			names: []asn1.RawValue{dnsName, {Class: asn1.ClassApplication, Tag: 6, Bytes: []byte(spiffeID)}},
		},
		{
			name:  "private tag 6",
			names: []asn1.RawValue{dnsName, {Class: asn1.ClassPrivate, Tag: 6, Bytes: []byte(spiffeID)}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exts := sanExtension(t, tc.names...)
			got, err := GetURINamesFromExtensions(&exts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
