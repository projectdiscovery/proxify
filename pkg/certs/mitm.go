package certs

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/google/martian/v3/mitm"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cert *x509.Certificate
	pkey *rsa.PrivateKey
)

// GetMitMConfig returns mitm config for martian
func GetMitMConfig() *mitm.Config {
	cfg, err := mitm.NewConfig(cert, pkey)
	if err != nil {
		gologger.Fatal().Msgf("failed to create mitm config")
	}
	return cfg
}

func SaveCAToFile(filename string) error {
	buffer := &bytes.Buffer{}
	_ = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return os.WriteFile(filename, buffer.Bytes(), 0600)
}

// generateCertificate creates new certificate
func generateCertificate(certFile, keyFile string) error {
	var err error
	cert, pkey, err = mitm.NewAuthority("Proxify CA", organization, time.Duration(24*365)*time.Hour)
	if err != nil {
		gologger.Fatal().Msgf("failed to generate CA Certificate")
	}
	if err = SaveCAToFile(certFile); err != nil {
		gologger.Fatal().Msgf("failed to save certFile to disk got %v", err)
	}
	kf, err := os.OpenFile(keyFile, os.O_WRONLY, 0600)
	if err != nil {
		gologger.Fatal().Msgf("failed to load open %v while saving private key got %v", keyFile, err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pkey)}); err != nil {
		gologger.Fatal().Msgf("failed to write private key to file got %v", err)
	}
	_ = kf.Close()
	return nil
}

func readCertNKeyFromDisk(certFile, keyFile string) error {
	block, err := readPemFromDisk(certFile)
	if err != nil {
		return err
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("expired certificate found")
	}
	block, err = readPemFromDisk(keyFile)
	if err != nil {
		return err
	}
	pkey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

func readPemFromDisk(filename string) (*pem.Block, error) {
	Bin, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(Bin)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block got nil")
	}
	return block, nil
}

func LoadCerts(dir string) {
	certFile := path.Join(dir, caCertName)
	keyFile := path.Join(dir, caKeyName)

	if !fileutil.FileExists(certFile) || !fileutil.FileExists(keyFile) {
		generateCertificate(certFile, keyFile)
		return
	}
	if err := readCertNKeyFromDisk(certFile, keyFile); err != nil {
		gologger.Print().Msgf("malformed/expired certificate found generating new ones\nNote: Certificates must be reinstalled")
	}
	if cert == nil || pkey == nil {
		gologger.Fatal().Msgf("something went wrong, cannot start proxify")
	}
}
