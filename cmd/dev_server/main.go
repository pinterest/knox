package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"expvar"
	"flag"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

const caCert = `-----BEGIN CERTIFICATE-----
MIICZDCCAgqgAwIBAgIUV/9Ovq6Y38sy7l+TBnGzibrsStQwCgYIKoZIzj0EAwIw
fjELMAkGA1UEBhMCVVMxFjAUBgNVBAgTDVNhbiBGcmFuY2lzY28xCzAJBgNVBAcT
AkNBMRgwFgYDVQQKEw9NeSBDb21wYW55IE5hbWUxEzARBgNVBAsTCk9yZyBVbml0
IDIxGzAZBgNVBAMTEnVzZU9ubHlJbkRldk9yVGVzdDAeFw0xNjA0MjgxODQ0MDBa
Fw0yMTA0MjcxODQ0MDBaMH4xCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1TYW4gRnJh
bmNpc2NvMQswCQYDVQQHEwJDQTEYMBYGA1UEChMPTXkgQ29tcGFueSBOYW1lMRMw
EQYDVQQLEwpPcmcgVW5pdCAyMRswGQYDVQQDExJ1c2VPbmx5SW5EZXZPclRlc3Qw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATjBG3vEwKV5PzOZk7Uf/8JGdX1YZpV
Zk7PtpfTYchIp40bY2DV+iYb/bEaxytLECaIoLS2FRR/ZLCzMBNGBJfao2YwZDAO
BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUTS1i
WIo7D/ErlcqpYD12QGouqlYwHwYDVR0jBBgwFoAUTS1iWIo7D/ErlcqpYD12QGou
qlYwCgYIKoZIzj0EAwIDSAAwRQIhALxAY3gtSz6VRND4DsMKaeHmuYGFctwdAWeL
zvRXTUCdAiAXgynic2vnOt/jQXoOKCIgfxGytpAaDwZv8RgdI5yg8g==
-----END CERTIFICATE-----`

var gitSha = expvar.NewString("version")
var service = expvar.NewString("service")

var (
	flagAddr = flag.String("http", ":9000", "HTTP port to listen on")
)

const (
	authTimeout = 10 * time.Second // Calls to auth timeout after 10 seconds
	serviceName = "knox_dev"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	flag.Parse()
	accLogger, errLogger := setupLogging("dev", serviceName)

	dbEncryptionKey := []byte("testtesttesttest")
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)

	tlsCert, tlsKey, err := buildCert()
	if err != nil {
		errLogger.Fatal("Failed to make TLS key or cert: ", err)
	}

	db := keydb.NewTempDB()

	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(caCert))

	decorators := [](func(http.HandlerFunc) http.HandlerFunc){
		server.Logger(accLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication([]auth.Provider{auth.NewMTLSAuthProvider(certPool), auth.NewGitHubProvider(authTimeout)}),
	}

	r := server.GetRouter(cryptor, db, decorators)

	http.Handle("/", r)

	errLogger.Fatal(serveTLS(tlsCert, tlsKey, *flagAddr))
}

func setupLogging(gitSha, service string) (*log.Logger, *log.Logger) {
	accLogger := log.New(os.Stderr, "", 0)
	accLogger.SetVersion(gitSha)
	accLogger.SetService(service)

	errLogger := log.New(os.Stderr, "", 0)
	errLogger.SetVersion(gitSha)
	errLogger.SetService(service)
	return accLogger, errLogger
}

func buildCert() (certPEMBlock, keyPEMBlock []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = []string{"localhost"}

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

// serveTLS sets up TLS using Mozilla reccommendations and then serves http
func serveTLS(certPEMBlock, keyPEMBlock []byte, httpPort string) error {
	// This TLS config disables RC4 and SSLv3.
	tlsConfig := &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	var err error
	tlsConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: httpPort, Handler: nil, TLSConfig: tlsConfig}

	return server.ListenAndServeTLS("", "")
}
