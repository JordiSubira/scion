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

package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadX509KeyPair(t *testing.T) {
	if *update {
		t.Skip("test crypto is being updated")
	}

	getChain := func(t *testing.T) []*x509.Certificate {
		return xtest.LoadChain(t,
			filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
	}

	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
	key := loadRawKey(t, filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/cp-as.key"))
	chain := getChain(t)

	_ = trc
	_ = chain

	testCases := map[string]struct {
		keyLoader    func(mctrcl *gomock.Controller) trust.KeyLoader
		db           func(mctrcl *gomock.Controller) trust.DB
		assertFunc   assert.ErrorAssertionFunc
		expectedCert func() *tls.Certificate
	}{
		"valid": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				certPEM, keyPEM := trust.PairToEncodedPEM(chain, key)
				certTLS, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					panic("error loading expected pair")
				}
				return &certTLS
			},
		},
		"newest": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				longer := getChain(t)
				longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
				longer[0].Signature = nil
				longer[0].SubjectKeyId = []byte("longer")

				shorter := getChain(t)
				shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
				shorter[0].SubjectKeyId = []byte("shorter")

				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				longer := getChain(t)
				longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
				longer[0].SubjectKeyId = []byte("longer")
				certPEM, keyPEM := trust.PairToEncodedPEM(chain, key)
				certTLS, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					panic("error loading expected pair")
				}
				return &certTLS
			},
		},
		"select best from grace": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				longer := getChain(t)
				longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
				longer[0].SubjectKeyId = []byte("longer")

				shorter := getChain(t)
				shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
				shorter[0].SubjectKeyId = []byte("shorter")

				trc2 := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
				trc2.TRC.ID.Serial = 2
				trc2.TRC.Validity.NotBefore = time.Now()
				trc2.TRC.GracePeriod = 5 * time.Minute

				roots, err := trc2.TRC.RootCerts()
				require.NoError(t, err)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				for _, root := range roots {
					root.PublicKey = key.Public()
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc2, nil,
				)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			assertFunc: assert.NoError,
			expectedCert: func() *tls.Certificate {
				longer := getChain(t)
				longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
				longer[0].SubjectKeyId = []byte("longer")
				certPEM, keyPEM := trust.PairToEncodedPEM(chain, key)
				certTLS, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					panic("error loading expected pair")
				}
				return &certTLS
			},
		},
		"no keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"rsa key": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)

				priv, err := rsa.GenerateKey(rand.Reader, 512)
				require.NoError(t, err)
				privRaw, err := x509.MarshalPKCS8PrivateKey(priv)
				require.NoError(t, err)

				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{privRaw}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					trc, nil,
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"no chain found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(nil, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("fail"))
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC not found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, TRCIDMatcher{ISD: 1}).Return(
					cppki.SignedTRC{}, nil)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.Chain error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyLoader {
				loader := mock_trust.NewMockKeyLoader(mctrl)
				loader.EXPECT().GetKeys(gomock.Any()).Return(
					[][]byte{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					TRCIDMatcher{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					nil, serrors.New("fail"),
				)
				return db
			},
			assertFunc: assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			provider := trust.X509KeyPairProvider{
				IA:      xtest.MustParseIA("1-ff00:0:110"),
				DB:      tc.db(mctrl),
				Timeout: 5 * time.Second,
				Loader:  tc.keyLoader(mctrl),
			}
			tlsCert, err := provider.LoadX509KeyPair()
			tc.assertFunc(t, err)
			assert.Equal(t, tc.expectedCert(), tlsCert)
		})
	}
}

func loadRawKey(t *testing.T, file string) []byte {
	raw, err := ioutil.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		panic("no valid private key block")
	}
	return block.Bytes
}
