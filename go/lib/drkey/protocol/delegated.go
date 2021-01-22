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

package protocol

import (
	"errors"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Delegated implements the level 2 drkey derivation from level 1, without DS. It relies on the
// Standard implementation to derive the DS from the level 1 key.
type Delegated struct{}

// DeriveLvl2 derives the level 2 DRKey without passing through a delegation secret.
func (p Delegated) DeriveLvl2(meta drkey.Lvl2Meta, key drkey.Lvl1Key) (drkey.Lvl2Key, error) {
	metaForDS := meta
	metaForDS.KeyType = drkey.AS2AS
	dsKey, err := Standard{}.DeriveLvl2(metaForDS, key)
	if err != nil {
		return drkey.Lvl2Key{}, serrors.WrapStr("Error deriving DS", err)
	}
	ds := drkey.DelegationSecret{
		Protocol: meta.Protocol,
		Epoch:    meta.Epoch,
		SrcIA:    meta.SrcIA,
		DstIA:    meta.DstIA,
		Key:      dsKey.Key,
	}
	return p.DeriveLvl2FromDS(meta, ds)
}

// DeriveLvl2FromDS will derive the level 2 key from a delegation secret.
func (p Delegated) DeriveLvl2FromDS(meta drkey.Lvl2Meta, ds drkey.DelegationSecret) (
	drkey.Lvl2Key, error) {

	h, err := scrypto.InitMac([]byte(ds.Key))
	if err != nil {
		return drkey.Lvl2Key{}, err
	}

	pLen := 0
	buffs := [][]byte{}
	// add to buffs in reverse order:
	switch meta.KeyType {
	case drkey.Host2Host:
		if len(meta.SrcHost) == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a src host, but it is empty")
		}
		buffs = [][]byte{
			meta.SrcHost,
			{byte(len(meta.SrcHost))},
		}
		pLen += len(meta.SrcHost) + 1
		fallthrough
	case drkey.AS2Host:
		if len(meta.DstHost) == 0 {
			return drkey.Lvl2Key{}, errors.New("Level 2 DRKey requires a dst host, but it is empty")
		}
		buffs = append(buffs,
			meta.DstHost,
			[]byte{byte(len(meta.DstHost))})
		pLen += len(meta.DstHost) + 1
	case drkey.AS2AS:
		return drkey.Lvl2Key{
			Lvl2Meta: meta,
			Key:      ds.Key,
		}, nil
	default:
		return drkey.Lvl2Key{}, serrors.New("Unknown DRKey type")
	}
	all := make([]byte, pLen)
	pLen = 0
	for i := len(buffs) - 1; i >= 0; i-- {
		copy(all[pLen:], buffs[i])
		pLen += len(buffs[i])
	}
	h.Write(all)
	return drkey.Lvl2Key{
		Lvl2Meta: meta,
		Key:      drkey.DRKey(h.Sum(nil)),
	}, nil
}
