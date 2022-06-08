package fake

import (
	"crypto/aes"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// KeySize in bytes
const KeySize = aes.BlockSize

// Epoch represents a validity period.
type Epoch struct {
	cppki.Validity
}

// Equal returns true if both Epochs are identical.
func (e Epoch) Equal(other Epoch) bool {
	return e.NotBefore == other.NotBefore &&
		e.NotAfter == other.NotAfter
}

// NewEpoch constructs an Epoch from its uint32 encoded begin and end parts.
func NewEpoch(begin, end uint32) Epoch {
	return Epoch{
		cppki.Validity{
			NotBefore: util.SecsToTime(begin).UTC(),
			NotAfter:  util.SecsToTime(end).UTC(),
		},
	}
}

// Contains indicates whether the time point is inside this Epoch.
func (e *Epoch) Contains(t time.Time) bool {
	return e.Validity.Contains(t)
}

// Protocol is the 2-byte size protocol identifier
type Protocol uint16

// DRKey protocol types.
const (
	Generic Protocol = iota
	SCMP
)

// Key represents a raw binary key
type Key [16]byte

func (k Key) String() string {
	return "[redacted key]"
}

const drkeySalt = "Derive DRKey Key"

// / Lvl1Meta contains metadata to obtain a lvl1 key.
type Lvl1Meta struct {
	Validity     time.Time
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
}

// Lvl1Key represents a level 1 DRKey.
type Lvl1Key struct {
	Epoch        Epoch
	ProtoId      Protocol
	SrcIA, DstIA addr.IA
	Key          Key
}

// Lvl2Meta contains metadata to obtain end host keys
// (aka lvl2/3 keys).
type Lvl2Meta struct {
	ProtoId  Protocol
	Validity time.Time
	SrcIA    addr.IA
	DstIA    addr.IA
}

// ASHost represents the associated information for the ASHost key.
type ASHostMeta struct {
	Lvl2Meta
	DstHost string
}

// ASHost represents a ASHost key.
type ASHostKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	DstHost string
	Key     Key
}

// HostASMeta represents the associated information for the HostAS key.
type HostASMeta struct {
	Lvl2Meta
	SrcHost string
}

// HostASKey represents a Host-AS key.
type HostASKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	SrcHost string
	Key     Key
}

// HostHostMeta represents the associated information for the HostHostMeta key.
type HostHostMeta struct {
	Lvl2Meta
	SrcHost string
	DstHost string
}

// HostHostKey represents a Host-Host DRKey.
type HostHostKey struct {
	ProtoId Protocol
	Epoch   Epoch
	SrcIA   addr.IA
	DstIA   addr.IA
	SrcHost string
	DstHost string
	Key     Key
}
