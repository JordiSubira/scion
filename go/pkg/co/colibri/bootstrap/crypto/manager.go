package crypto

import (
	"github.com/scionproto/scion/go/lib/drkey"
)

type AsymProvider interface {
	EncryptLvl1Key(lvl1 drkey.Lvl1Key, nonce, pubkey, privkey []byte) ([]byte, error)
	DecryptLvl1Key(ciphertext, nonce, pubkey, privkey []byte) (drkey.Lvl1Key, error)
}
