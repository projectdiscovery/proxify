// Package certs implements a certificate signing authority implementation
// to sign MITM-ed hosts certificates using a self-signed authority.
//
// It uses an LRU-based certificate caching implementation for
// caching the generated certificates for frequently accessed hosts.
package certs

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Manager implements a certificate signing authority for TLS Mitm.
type Manager struct {
	cert  *tls.Certificate
	cache *lru.Cache
}

// Options contains the configuration options for certificate signing client.
type Options struct {
	CacheSize int
	Directory string
}

const (
	caKeyName  = "cakey.pem"
	caCertName = "cacert.pem"
)

// New creates a new certificate manager signing client instance
func New(options *Options) (*Manager, error) {
	manager := &Manager{}

	certFile := filepath.Join(options.Directory, caCertName)
	keyFile := filepath.Join(options.Directory, caKeyName)

	if !fileutil.FileExists(certFile) || !fileutil.FileExists(keyFile) {
		if err := manager.createAuthority(certFile, keyFile); err != nil {
			return nil, errors.Wrap(err, "could not create certificate authority")
		}
	}
retryRead:
	cert, err := manager.readCertificateDisk(certFile, keyFile)
	if err != nil {
		// Check if we have an expired cert and regenerate
		if err == errExpiredCert {
			if err := manager.createAuthority(certFile, keyFile); err != nil {
				return nil, errors.Wrap(err, "could not create certificate authority")
			}
			goto retryRead
		}
		return nil, errors.Wrap(err, "could not read certificate authority")
	}

	cache, err := lru.New(options.CacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "could not create lru cache")
	}
	return &Manager{cert: cert, cache: cache}, nil
}

// GetCA returns the CA certificate in PEM Encoded format.
func (m *Manager) GetCA() (tls.Certificate, []byte) {
	buffer := &bytes.Buffer{}

	_ = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Certificate[0]})
	return *m.cert, buffer.Bytes()
}

// Get returns a certificate for the current host.
func (m *Manager) Get(host string) (*tls.Certificate, error) {
	if value, ok := m.cache.Get(host); ok {
		return value.(*tls.Certificate), nil
	}
	cert, err := m.signCertificate(host)
	if err != nil {
		return nil, err
	}
	m.cache.Add(host, cert)
	return cert, nil
}

// TLSConfigFromCA generates a spoofed TLS certificate for a host
func (m *Manager) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		hostname := stripPort(host)

		value, ok := m.cache.Get(host)
		if !ok {
			certificate, err := m.signCertificate(hostname)
			if err != nil {
				return nil, err
			}
			value = certificate
			m.cache.Add(host, certificate)
		}

		return &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{*value.(*tls.Certificate)}}, nil
	}
}

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}
