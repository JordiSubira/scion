// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trust

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

const defaultTimeout = 5 * time.Second

// X509KeyPairLoader provides a certificate to be presented during TLS handshake.
type X509KeyPairLoader interface {
	LoadX509KeyPair(extKeyUsages []x509.ExtKeyUsage) (*tls.Certificate, error)
}

// TLSCryptoManager implements callbacks which will be called during TLS handshake.
type TLSCryptoManager struct {
	Loader  X509KeyPairLoader
	DB      DB
	Timeout time.Duration
}

// NewTLSCryptoManager returns a new instance with the defaultTimeout.
func NewTLSCryptoManager(loader X509KeyPairLoader, db DB) *TLSCryptoManager {
	return &TLSCryptoManager{
		DB:      db,
		Loader:  loader,
		Timeout: defaultTimeout,
	}
}

// GetCertificate retrieves a certificate to be presented during TLS handshake.
func (m *TLSCryptoManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c, err := m.Loader.LoadX509KeyPair([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return nil, serrors.WrapStr("loading server key pair", err)
	}
	return c, nil
}

// GetClientCertificate retrieves a client certificate to be presented during TLS handshake.
func (m *TLSCryptoManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate,
	error) {
	c, err := m.Loader.LoadX509KeyPair([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return nil, serrors.WrapStr("loading client key pair", err)
	}
	return c, nil
}

func (m *TLSCryptoManager) VerifyServerCertificate(rawCerts [][]byte,
	_ [][]*x509.Certificate) error {
	return m.verifyPeerCertificate(rawCerts, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (m *TLSCryptoManager) VerifyClientCertificate(rawCerts [][]byte,
	_ [][]*x509.Certificate) error {
	return m.verifyPeerCertificate(rawCerts, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// VerifyPeerCertificate verifies the certificate presented by the peer during TLS handshake,
// based on the TRC.
func (m *TLSCryptoManager) verifyPeerCertificate(rawCerts [][]byte,
	extKeyUsages []x509.ExtKeyUsage) error {
	chain := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return serrors.WrapStr("parsing peer certificate", err)
		}
		chain[i] = cert
	}
	if err := verifyExtendedKeyUsage(chain[0], extKeyUsages); err != nil {
		return err
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return serrors.WrapStr("extracting ISD-AS from peer certificate", err)
	} else if ia == nil {
		return serrors.New("ISD-AS no present in peer certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.Timeout)
	defer cancel()
	trcs, _, err := activeTRCs(ctx, m.DB, ia.I)
	if err != nil {
		return serrors.WrapStr("loading TRCs", err)
	}
	if err := verifyChain(chain, trcs); err != nil {
		return serrors.WrapStr("verifying chains", err)
	}
	return nil
}

func verifyChain(chain []*x509.Certificate, trcs []cppki.SignedTRC) error {
	var errs serrors.List
	for _, trc := range trcs {
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: &trc.TRC}); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return errs.ToError()
}

// verifyExtendedKeyUsage return an error if the certifcate extended key usages do not
// include any requested extended key usage.
func verifyExtendedKeyUsage(cert *x509.Certificate, extKeyUsages []x509.ExtKeyUsage) error {
	for _, extKeyUsage := range extKeyUsages {
		for _, certExtKeyUsage := range cert.ExtKeyUsage {
			if extKeyUsage == x509.ExtKeyUsageAny || extKeyUsage == certExtKeyUsage {
				return nil
			}
		}
	}
	return serrors.New("Invalid certificate key usages")
}

// FileLoader loads key pair from file
type FileLoader struct {
	CertFile string
	KeyFile  string
}

// LoadX509KeyPair returns the TLS certificate to be provided during a TLS handshake.
func (l FileLoader) LoadX509KeyPair() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
	if err != nil {
		return nil, serrors.WrapStr("loading certificates for DRKey gRPCs", err)
	}
	return &cert, nil
}
