package uri

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestGetKeyUsageExtensionsFromCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	der, err := x509.CreateCertificate(rand.Reader,
		template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	keyUsageExtensions := GetKeyUsageExtensionsFromCertificate(cert)
	if len(keyUsageExtensions) != 1 {
		t.Fatalf("Expected to get one Key Usage extension, but got: %v", len(keyUsageExtensions))
	}
}
