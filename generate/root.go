package generate

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// Root generates a root cert
func Root(csr *x509.CertificateRequest, key crypto.Signer, start, finish time.Time) (cert *x509.Certificate, err error) {
	if csr == nil || key == nil {
		err = fmt.Errorf("cannot use nil input to create root CA")
		return
	}
	root := &x509.Certificate{
		Version:         3,
		Subject:         csr.Subject,
		PublicKey:       key.Public(),
		SerialNumber:    big.NewInt(1),
		Issuer:          csr.Subject,
		NotBefore:       start,
		NotAfter:        finish,
		KeyUsage:        x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageContentCommitment | x509.KeyUsageDataEncipherment | x509.KeyUsageDecipherOnly | x509.KeyUsageDigitalSignature | x509.KeyUsageEncipherOnly | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		Extensions:      csr.Extensions,
		ExtraExtensions: csr.ExtraExtensions,
		// ExtKeyUsage: , // TODO
		IsCA: true,
		// SubjectKeyId: ,
		// AuthorityKeyId: ,
		// OCSPServer: ,
		// IssuingCertificateURL: ,
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		// CRLDistributionPoints: ,
		// PolicyIdentifiers: ,
	}
	var certBytes []byte
	certBytes, err = x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certBytes)
	return
}
