package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"
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
		{
			name:  "constructed context-specific tag 6",
			names: []asn1.RawValue{dnsName, {Class: asn1.ClassContextSpecific, Tag: 6, IsCompound: true, Bytes: []byte(spiffeID)}},
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

func TestSpiffeProviderRejectsSmuggledURISAN(t *testing.T) {
	const spiffeID = "spiffe://example.com/prod/super-admin"
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	dnsName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("worker1.example.com")}
	tests := []struct {
		name    string
		uri     asn1.RawValue
		wantErr bool
	}{
		{
			name: "context-specific URI",
			uri:  asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(spiffeID)},
		},
		{
			name:    "universal tag 6",
			uri:     asn1.RawValue{Class: asn1.ClassUniversal, Tag: 6, Bytes: []byte(spiffeID)},
			wantErr: true,
		},
		{
			name:    "constructed context-specific tag 6",
			uri:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, IsCompound: true, Bytes: []byte(spiffeID)},
			wantErr: true,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafTmpl := &x509.Certificate{
				SerialNumber:    big.NewInt(int64(i + 2)),
				Subject:         pkix.Name{CommonName: "worker1.example.com"},
				NotBefore:       now.Add(-time.Hour),
				NotAfter:        now.Add(time.Hour),
				ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				ExtraExtensions: sanExtension(t, dnsName, tc.uri),
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(leafDER)
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest("GET", "http://localhost/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

			p, err := NewSpiffeAuthProvider(caPool).Authenticate("ANYTHING", req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("authenticated as %q, want error", p.GetID())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.GetID() != spiffeID {
				t.Errorf("got principal %q, want %q", p.GetID(), spiffeID)
			}
		})
	}
}
