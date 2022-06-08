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

// Package fake implements a interface for fake DRKey derivation. This is
// intended to serve as a mock interface to program against, in the absence of
// the real DRKey implementation.
// The keys returned here are simply the concatenated inputs used to generate
// them, arbitrarily truncated so they fit the 16-byte key size. In the real
// DRKey implementation, the keys would be created by repeated invocations of a
// PRF (AES).
package fake

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Deriver is the interface for DRKeys that can be locally derived.
type Deriver interface {
	DeriveLvl1(meta Lvl1Meta, key Key) (Key, error)
	DeriveASHost(meta ASHostMeta, key Key) (Key, error)
	DeriveHostAS(meta HostASMeta, key Key) (Key, error)
	DeriveHostToHost(dstHost string, key Key) (Key, error)
}

type KeyProvider interface {
	GetSV() Key
}

type Provider struct{}

func (p *Provider) GetSV() Key {
	return Key{}
}

func NewDeriver() *deriver {
	return &deriver{}
}

type deriver struct {
	buf [32]byte
}

func (p *deriver) DeriveLvl1(meta Lvl1Meta, key Key) (Key, error) {
	len := inputDeriveLvl1(p.buf[:], meta)
	outKey, err := deriveKey(p.buf[:], len, key)
	return outKey, err
}

func inputDeriveLvl1(buf []byte, meta Lvl1Meta) int {
	_ = buf[aes.BlockSize-1]
	buf[0] = byte(asToAs)
	binary.BigEndian.PutUint64(buf[1:], uint64(meta.DstIA))
	copy(buf[9:], zeroBlock[:])

	return aes.BlockSize
}

func (p *deriver) inputDeriveLvl2(input []byte, derType keyType,
	host hostAddr) int {
	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	input[1] = uint8(host.AddrType&0x3)<<2 | uint8(host.AddrLen&0x3)
	copy(input[2:], hostAddr)
	copy(input[2+l:inputLength], zeroBlock[:])

	return inputLength
}

// DeriveASHost returns the ASHost derived key.
func (p *deriver) DeriveASHost(meta ASHostMeta, key Key) (Key, error) {
	host, err := packtoHostAddr(meta.DstHost)
	if err != nil {
		return Key{}, serrors.WrapStr("parsing dst host", err)
	}
	len := p.inputDeriveLvl2(p.buf[:], asToHost, host)
	outKey, err := deriveKey(p.buf[:], len, key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (p *deriver) DeriveHostAS(meta HostASMeta, key Key) (Key, error) {
	host, err := packtoHostAddr(meta.SrcHost)
	if err != nil {
		return Key{}, serrors.WrapStr("parsing src host", err)
	}
	len := p.inputDeriveLvl2(p.buf[:], hostToAS, host)
	outKey, err := deriveKey(p.buf[:], len, key)
	return outKey, err
}

// DeriveHostToHost returns the HostHost derived key.
func (p *deriver) DeriveHostToHost(dstHost string, key Key) (Key, error) {
	host, err := packtoHostAddr(dstHost)
	if err != nil {
		return Key{}, serrors.WrapStr("deriving input H2H", err)
	}
	len := inputDeriveHostToHost(p.buf[:], host)
	outKey, err := deriveKey(p.buf[:], len, key)
	return outKey, err
}
