package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"
)

// Constants used for the SSL Certificates
const (
	bits          = 2048
	organization  = "ProjectDiscovery, Inc."
	country       = "IN"
	province      = "Maharashtra"
	locality      = "B.P.Lane"
	streetAddress = "321, B.P.Lane West."
	postalCode    = "400003"
)

// createCertificateAuthority creates a new certificate authority
func (m *Manager) createAuthority(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(365*24) * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{postalCode},
			CommonName:    organization,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
}

var errExpiredCert = errors.New("expired cert error")

// readCertificateDisk reads a certificate and key file from disk
func (m *Manager) readCertificateDisk(certFile string, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	// Check the expiration.
	if time.Now().After(cert.Leaf.NotAfter) {
		return nil, errExpiredCert
	}
	return &cert, nil
}

// signCertificate signs a TLS Certificate for a host
func (m *Manager) signCertificate(host string) (*tls.Certificate, error) {
	x509ca, err := x509.ParseCertificate(m.cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(365*24) * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{postalCode},
			CommonName:    host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	certpriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, x509ca, &certpriv.PublicKey, m.cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{derBytes, m.cert.Certificate[0]}, PrivateKey: certpriv}, nil
}
