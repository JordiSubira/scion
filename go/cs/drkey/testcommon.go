// Copyright 2019 ETH Zurich
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

package drkey

import (
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/drkeystorage"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	id111 = keyconf.ID{
		IA:      xtest.MustParseIA("1-ff00:0:111"),
		Usage:   keyconf.ASDecryptionKey,
		Version: 1,
	}
	id112 = keyconf.ID{
		IA:      xtest.MustParseIA("1-ff00:0:112"),
		Usage:   keyconf.ASDecryptionKey,
		Version: 1,
	}
)

func getTestMasterSecret() []byte {
	return []byte{0, 1, 2, 3}
}

// SecretValueTestFactory works as a SecretValueFactory but uses a user-controlled-variable instead
// of time.Now when calling GetSecretValue.
type SecretValueTestFactory struct {
	SecretValueFactory
	Now time.Time
}

func (f *SecretValueTestFactory) GetSecretValue(t time.Time) (drkey.SV, error) {
	return f.SecretValueFactory.GetSecretValue(f.Now)
}

func getSecretValueTestFactory() drkeystorage.SecretValueFactory {
	return &SecretValueTestFactory{
		SecretValueFactory: *NewSecretValueFactory(getTestMasterSecret(), 10*time.Second),
		Now:                util.SecsToTime(0),
	}
}

func loadCertsKeys(t *testing.T) (*cert.AS, []byte, *cert.AS, []byte) {
	loadChain := func(filename string, t *testing.T) *cert.AS {
		var err error
		var AS *cert.AS

		rawChain, err := ioutil.ReadFile(filename)
		require.NoError(t, err)
		chain, err := cert.ParseChain(rawChain)
		require.NoError(t, err)
		AS, err = chain.AS.Encoded.Decode()
		require.NoError(t, err)
		return AS
	}
	cert111 := loadChain("testdata/as111/certs/ISD1-ASff00_0_111-V1.crt", t)
	privateKey111, err := keyconf.LoadKeyFromFile(filepath.Join("testdata/as111/keys",
		keyconf.PrivateKeyFile(keyconf.ASDecryptionKey, id111.Version)),
		keyconf.PrivateKey, id111)
	require.NoError(t, err)

	cert112 := loadChain("testdata/as112/certs/ISD1-ASff00_0_112-V1.crt", t)
	privateKey112, err := keyconf.LoadKeyFromFile(filepath.Join("testdata/as112/keys",
		keyconf.PrivateKeyFile(keyconf.ASDecryptionKey, id112.Version)),
		keyconf.PrivateKey, id112)
	require.NoError(t, err)
	return cert111, privateKey111.Bytes, cert112, privateKey112.Bytes
}
