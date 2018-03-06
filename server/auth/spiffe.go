package auth

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// This code is from https://github.com/spiffe/go-spiffe

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func getURINamesFromSANExtension(sanExtension []byte) (uris []string, err error) {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	var rest []byte
	if rest, err = asn1.Unmarshal(sanExtension, &seq); err != nil {
		return uris, err
	} else if len(rest) != 0 {
		err = errors.New("x509: trailing data after X.509 extension")
		return uris, err
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return uris, err
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return uris, err
		}
		if v.Tag == 6 {
			uris = append(uris, string(v.Bytes))
		}
	}

	return uris, err
}

// GetURINamesFromExtensions retrieves URIs from the SAN extension of a slice of extensions
func GetURINamesFromExtensions(extensions *[]pkix.Extension) (uris []string, err error) {
	for _, ext := range *extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			uris, err = getURINamesFromSANExtension(ext.Value)
			if err != nil {
				return uris, err
			}
		}
	}

	return uris, nil
}
