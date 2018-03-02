package uri

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"strings"
	"testing"
)

func getCertificateFromFile(t *testing.T, certFilePath string) string {
	certificateString, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		t.Fatal(err)
	}

	return string(certificateString)
}

const golden = "spiffe://dev.acme.com/path/service"

func TestGetURINamesFromPEM(t *testing.T) {
	certPEM := getCertificateFromFile(t, "../testdata/leaf.cert.pem")

	uris, err := GetURINamesFromPEM(string(certPEM))
	if err != nil {
		t.Error(err)
	}

	if len(uris) == 1 {
		if uris[0] != golden {
			t.Fatalf("Expected '%v' but got '%v'", golden, uris[0])
		}
	} else {
		t.Fatalf("Expected 1 URI but got '%v'", len(uris))
	}

	certPEM = getCertificateFromFile(t, "../testdata/intermediate.cert.pem")
	uris, err = GetURINamesFromPEM(string(certPEM))
	if err == nil {
		t.Fatal("Expected to fail")
	}

	if len(uris) > 0 {
		t.Fatalf("Expected to have no URIs but got %v URIs", len(uris))
	}
}

const (
	goodCert = `
-----BEGIN CERTIFICATE-----
MIIE1DCCArygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVVMx
FzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMRcwFQYDVQQDDA5JbnRlcm1lZGlhZXRD
QTAeFw0xNzA3MTkxNjUwMjBaFw0xNzA3MjkxNjUwMjBaMDUxCzAJBgNVBAYTAlVT
MRcwFQYDVQQKDA50ZXN0MS5hY21lLmNvbTENMAsGA1UEAwwEYmxvZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKm8P47lABp4+rz2nN+QYrxedbaFVWoF
FuoSkqcHsafMwbMrN+kI6wJVtlbwviDvxWFJ92q0H71QNFybTsmof3KUN/kYCp7P
+LKhBrN0ttWI5q6v5eDrjN0VdtVdnlZOYmJFbvETOgfK/qXKNRRM8HYW0tdqrtEw
CR5dIu53xVUSViBdwXpuy2c5W2mFn1gxTpdW+3hbZsL1pHrU9qPWLtTgl/KY8kjs
I7KW1cIcinE4SJomhB5L/4emhxKGY+kEa2+fN9IPjjvKSMOw9kiBKk1GHZcIY5EA
O3TIfUk3fysPzi5qA0su/bNtPQy1uXgXS10xUlV7pqRPvHjiNzgFkXUCAwEAAaOB
4zCB4DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRVQ91jSOONzVr1VGBdJOlPN+3XxTBg
BgNVHSMEWTBXgBQ13bfx50rDZO3y2CZdHPgleFUEoKE7pDkwNzELMAkGA1UEBhMC
VVMxFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0GCAhAA
MA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAtBgNVHREEJjAk
hiJzcGlmZmU6Ly9kZXYuYWNtZS5jb20vcGF0aC9zZXJ2aWNlMA0GCSqGSIb3DQEB
CwUAA4ICAQBp2+rtUxt1VmNM/vi6PwoSoYzWFmQ2nc4OM7bsOG4uppU54wRYZ+T7
c42EcrpyBgWn+rWHT1Hi6SNcmloKHydaUTZ4pq3IlKKnBNqwivU5BzIxYLDrhR/U
wd9s1tgmLvADqkQa1XjjSFn5Auoj1R640ry4qpw8IOusdm6wVhru4ssRnHX4E2uR
jQe7b3ws38aZhjtL78Ip0BB4yPxWJRp/WmEoT33QP+cZhA4IYWECxNODr6DSJeq2
VNu/6JACGrNfM2Sjt4Wxz+nIa3cKDNCA6PR8StTUTcoQ6ZBzpn+n/Q1xSRIOJz6N
hgfkyb9O7HAMdAP+TxehjqG3gh5Ky2DgYMCIZOztVzsuOb1DGJe/kGUKeRJLl2/O
QwkctwUOcVIxckNu6OvclriFzvoXObqO77XeCI2V1Vef0wGTWlWNOdbFa4708Y7f
5UdwInYQUi87RFDnc1SDU4Jrsv4KzZiv9FCfDg8pCBIdWpWT7DAuI0d7i7PZ+iFt
ZZ6sb/YDkyiDXU4ar/dja0FDE2r7jsN9D+FfW49+iDvXr4ELQyhZpW3Zr1Ojwm58
CJzjZwbRYiVwPBRsKmiYfO1E7esvw3CmjK5chfz8c40f6/APDro9ZmYNBRv2CnJy
t/DtcM/GpAhBbLP9Tk7kPB41v5fRIxVDo50Iz/qvkr37pQ4RsejSFg==
-----END CERTIFICATE-----
`
	badCert = `
-----BEGIN CERTIFICATE-----
MIIFiDCCA3CgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwNzELMAkGA1UEBhMCVVMx
FzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0EwHhcNMTcw
NzE5MTY1MDIwWhcNMTcxMDI3MTY1MDIwWjA/MQswCQYDVQQGEwJVUzEXMBUGA1UE
CgwOdGVzdDEuYWNtZS5jb20xFzAVBgNVBAMMDkludGVybWVkaWFldENBMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAph7QhbUKEjMWu2R/WXIc8RR0ymCL
njJTm0D5duTe7V2hklLhCo1KnZAjvDiDX9r85UfEja5MYItHmFF4HOZjSG6nY3Yg
Mm5hdJM7Jmv9NJR8DJInROabfRcaPdugs2UQ41jCEygIoWiZ9+yVlZ21MNW0yQdI
JHUNndQfXpS7dBdKw6fUqzZgpdzo86mAapZDIPL7gXv6MW8JhbvQCm+bg7SRIJOD
t/a1T0nHPNuwxdDWjGcmJEQRknffL8pheDlW9sMAd/4BtIeaWUEb3JjdDoaJ9SWU
tCgGRZOMnmry8npJnssyoLUtIPuk8949REOUB15nT94EhTtb1BMdiuD8P8HOHWC6
mcxpJCsKlCFmOQpES6WROqjckQJ0f/xPOdKAdI9W0Eg3TRtibV9XTfTvv8SPug9/
6FnkdpwF5xlJ/XcuW8GtpHUZNQ0NyxjUh2rQRAbwdTMeCvhx5fPHpT2kc6PIlzLw
h4Pt0Xvc1cNt2iJOVDqs75HvvUe4RYTfdqlK5385u/s2cxQrLuB4owJrTyrqc3yM
L/0h5JXr9P+T+axrd5WQWz2ngiaimli2vxZTR++RfBnyCgQGTiY+9UUOYYgHh6hJ
CGUPY77DsKuTfIXYlra+c65FKFAcZrC4vt1CLtBqW2mBy7U868c0L9PZ1g3+WGvA
FmnZA6MgUKQE0i0CAwEAAaOBlTCBkjAdBgNVHQ4EFgQUNd238edKw2Tt8tgmXRz4
JXhVBKAwHwYDVR0jBBgwFoAUUeBRd0yew4JtInksRTlbz71YwtEwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwLwYDVR0eAQH/BCUwI6AhMA+GDS5kZXYu
YWNtZS5jb20wDoYMZGV2LmFjbWUuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQBLljbI
ekm5/uhFbc/aCAlomwGkXFvyMXx7eD7Pimzn4H31nYvQ5ha2M0536JC/mH1xi7nK
OOMuSBAqjpALoRk4+3O5s6r9BN8KKhcI4jDKHqOSBe38K+Ad06B52yxYyL6YmJwk
Zlazf3KvExzUWS0t4ehNuI2HJvvwEitMpOF3hhwAYk3v/x2YBtpglH+yZC4Sfoma
ItjFWeD+DA0bVAMJiErz8Pq91avnC8SPpPXiPJVOaBhaNc8po6x6cwSqY6RnI2/K
0kUWXXH65Pz0JYru53ALzy4ouwJItcgMvzZPGVaojxEbGDrjXEkWIGresFrw1Ijr
IyrQUqWa9wW6ik+IQOb6m3FZYB8jMO7nhop9Ywm9uoSmFRg6RsP2AWHBMYP7lZqw
fx3HjrAvc3ycIZ2tSPkdLd5n8YuL31CVpa9aGwT5dYzIVd/eFUrCUIGV2j8XHgkL
gMPr8JhNPAG0B4rRpEXmK3HHybo3s0M8i80Lit98xzupNpng97xKT7jJBSinNTdt
/2uU7diHQM7aPNmNG+Wu3GXVt/MZuDMSFrh9AHl0A/Y4mNu6KKqRMJuvsfy/j1DD
fDGmAkjHrspiorTruphHk+cymJfjAGqZ0l6il4Wi5w4R5jrxnJMhkxbjr/PG5xCS
+ZKPPNZbpPIY54oQ2bHkuaQgzJ7us4ZW7gxgbw==
-----END CERTIFICATE-----
`
)

func TestFGetURINamesFromPEM(t *testing.T) {
	uris, err := FGetURINamesFromPEM(strings.NewReader(goodCert))
	if err != nil {
		t.Error(err)
	}

	if len(uris) == 1 {
		if uris[0] != golden {
			t.Fatalf("Expected '%v' but got '%v'", golden, uris[0])
		}
	} else {
		t.Fatalf("Expected 1 URI but got '%v'", len(uris))
	}

	uris, err = FGetURINamesFromPEM(strings.NewReader(badCert))
	if err == nil {
		t.Fatal("Expected to fail")
	}

	if len(uris) > 0 {
		t.Fatalf("Expected to have no URIs but got %v URIs", len(uris))
	}
}

func TestMarshalUriSANsAndGetURINamesFromExtensions(t *testing.T) {
	uriSans, err := MarshalUriSANs([]string{golden})
	if err != nil {
		t.Fatal(err)
	}

	extensions := []pkix.Extension{
		{
			Id:       []int{1, 2, 3, 4},
			Critical: false,
			Value:    []byte{0x01, 0x01, 1, 1, 1, 1},
		},
		{
			Id:       OidExtensionSubjectAltName,
			Value:    uriSans,
			Critical: true,
		},
	}

	uris, err := GetURINamesFromExtensions(&extensions)
	if err != nil {
		t.Fatal(err)
	}

	if uris[0] != golden {
		t.Fatalf("Expected to get: '%v' but obtained: '%v'", golden, uris[0])
	}
}

