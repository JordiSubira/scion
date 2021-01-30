// Copyright 2021 ETH Zurich
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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

type KeyLoader interface {
	GetKeys(ctx context.Context) ([][]byte, error)
}

type X509KeyPairProvider struct {
	IA      addr.IA
	DB      DB
	Timeout time.Duration
	Loader  KeyLoader
}

var _ X509KeyPairLoader = (*X509KeyPairProvider)(nil)

func (p X509KeyPairProvider) LoadX509KeyPair(extKeyUsages []x509.ExtKeyUsage) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	keys, err := p.Loader.GetKeys(ctx)
	if err != nil {
		log.Error("Error getting keys", "err", err)
		return nil, err
	}
	if len(keys) == 0 {
		log.Error("No available keys")
		return nil, serrors.New("no private key found")
	}

	trcs, _, err := activeTRCs(ctx, p.DB, p.IA.I)
	if err != nil {
		return nil, serrors.WrapStr("loading TRCs", err)
	}

	var bestChain []*x509.Certificate
	var bestKey []byte
	var bestExpiry time.Time
	for _, key := range keys {
		cert, expiry, err := p.bestKeyPair(ctx, trcs, extKeyUsages, key)
		if err != nil {
			log.Error("Error getting best key pair", "err", err)
			return nil, err
		}
		if cert == nil {
			continue
		}
		if bestChain != nil && bestExpiry.Before(expiry) {
			continue
		}
		bestChain = cert
		bestKey = key
		bestExpiry = expiry
	}
	if bestChain == nil {
		log.Error("No certificate chain found for DRKey")
		return nil, serrors.New("no certificate found for DRKey gRPC")
	}
	certPEM, keyPEM := PairToEncodedPEM(bestChain, bestKey)
	certTLS, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Error("Error loading best key pair", "err", err)
		return nil, serrors.WrapStr("loading certificates for DRKey gRPCs", err)
	}
	return &certTLS, nil
}

func (p X509KeyPairProvider) bestKeyPair(ctx context.Context, trcs []cppki.SignedTRC,
	extKeyUsages []x509.ExtKeyUsage, rawKey []byte) ([]*x509.Certificate, time.Time, error) {
	key, err := x509.ParsePKCS8PrivateKey(rawKey)
	if err != nil {
		return nil, time.Time{}, nil
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, time.Time{}, nil
	}
	skid, err := cppki.SubjectKeyID(signer.Public())
	if err != nil {
		return nil, time.Time{}, nil
	}
	chains, err := p.DB.Chains(ctx, ChainQuery{
		IA:           p.IA,
		SubjectKeyID: skid,
		Date:         time.Now(),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	opts := cppki.VerifyOptions{
		TRC:         &trcs[0].TRC,
		ExtKeyUsage: extKeyUsages,
	}
	chain := bestChain(chains, opts)
	if chain == nil && len(trcs) == 1 {
		return nil, time.Time{}, nil
	}
	var inGrace bool
	// Attempt to find a chain that is verifiable only in grace period. If we
	// have not found a chain yet.
	if chain == nil && len(trcs) == 2 {
		opts.TRC = &trcs[1].TRC
		chain = bestChain(chains, opts)
		if chain == nil {
			return nil, time.Time{}, nil
		}
		inGrace = true
	}
	expiry := min(chain[0].NotAfter, trcs[0].TRC.Validity.NotAfter)
	if inGrace {
		expiry = min(chain[0].NotAfter, trcs[0].TRC.GracePeriodEnd())
	}
	return chain, expiry, nil
}

func PairToEncodedPEM(chain []*x509.Certificate, key []byte) ([]byte, []byte) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	var certPEM []byte
	for _, cert := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return certPEM, keyPEM
}
