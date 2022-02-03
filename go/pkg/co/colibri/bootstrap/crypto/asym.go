package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
	"golang.org/x/crypto/nacl/box"
)

// Available asymmetric crypto algorithms. The values must be lower case.
const (
	Ed25519                    = "ed25519"
	Curve25519xSalsa20Poly1305 = "curve25519xsalsa20poly1305"
)

// Constants for nacl/box implementation of Curve25519xSalsa20Poly1305
const (
	NaClBoxNonceSize = 24
	NaClBoxKeySize   = 32
)

// Errors
var (
	ErrInvalidPubKeySize       = serrors.New("Invalid public key size")
	ErrInvalidPrivKeySize      = serrors.New("Invalid private key size")
	ErrInvalidSignatureSize    = serrors.New("Invalid signature size")
	ErrInvalidSignatureFormat  = serrors.New("Invalid signature format: sig[63]&224 should equal 0")
	ErrVerification            = serrors.New("Signature verification failed")
	ErrUnableToGenerateKeyPair = serrors.New("Unable to generate key pair")
	ErrUnableToDecrypt         = serrors.New("Unable to decrypt message")
	ErrUnsupportedAlgo         = serrors.New("Unsupported algorithm")
	ErrUnsupportedSignAlgo     = serrors.New("Unsupported signing algorithm")
	ErrUnsupportedEncAlgo      = serrors.New("Unsupported encryption algorithm")
	ErrInvalidNonceSize        = serrors.New("Invalid nonce size")
)

// GenKeyPair generates a public/private key pair.
func GenKeyPair(algo string) (common.RawBytes, common.RawBytes, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		pubkey, privkey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, serrors.Wrap(ErrUnableToGenerateKeyPair, err, "algo", algo)
		}
		return pubkey[:], privkey[:], nil
	case Ed25519:
		pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, serrors.Wrap(ErrUnableToGenerateKeyPair, err, "algo", algo)
		}
		return common.RawBytes(pubkey), common.RawBytes(privkey), nil
	default:
		return nil, nil, serrors.WithCtx(ErrUnsupportedAlgo, "algo", algo)
	}
}

// Encrypt takes a message, a nonce and a public/private keypair and
// returns the encrypted and authenticated message.
// Note: Nonce must be different for each message that is encrypted with the same key.
func Encrypt(msg, nonce, pubkey, privkey []byte, algo string) ([]byte, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		return box.Seal(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw), nil
	default:
		return nil, serrors.WithCtx(ErrUnsupportedEncAlgo, "algo", algo)
	}
}

// Decrypt decrypts a message for a given nonce and public/private keypair.
func Decrypt(msg, nonce, pubkey, privkey []byte, algo string) ([]byte, error) {
	switch strings.ToLower(algo) {
	case Curve25519xSalsa20Poly1305:
		nonceRaw, pubKeyRaw, privKeyRaw, err := prepNaClBox(nonce, pubkey, privkey)
		if err != nil {
			return nil, err
		}
		dec, ok := box.Open(nil, msg, nonceRaw, pubKeyRaw, privKeyRaw)
		if !ok {
			return nil, serrors.WithCtx(ErrUnableToDecrypt, "algo", algo)
		}
		return dec, nil
	default:
		return nil, serrors.WithCtx(ErrUnsupportedEncAlgo, "algo", algo)
	}
}

func prepNaClBox(nonce, pubkey, privkey []byte) (*[NaClBoxNonceSize]byte,
	*[NaClBoxKeySize]byte, *[NaClBoxKeySize]byte, error) {

	if len(nonce) != NaClBoxNonceSize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidNonceSize, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxNonceSize, "actual size",
			len(nonce))
	}
	if len(pubkey) != NaClBoxKeySize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidPubKeySize, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxKeySize, "actual size", len(pubkey))
	}
	if len(privkey) != NaClBoxKeySize {
		return nil, nil, nil, serrors.WithCtx(ErrInvalidPrivKeySize, "algo",
			Curve25519xSalsa20Poly1305, "expected size", NaClBoxKeySize, "actual size",
			len(privkey))
	}
	var nonceRaw [NaClBoxNonceSize]byte
	var pubKeyRaw, privKeyRaw [NaClBoxKeySize]byte
	copy(nonceRaw[:], nonce)
	copy(pubKeyRaw[:], pubkey)
	copy(privKeyRaw[:], privkey)
	return &nonceRaw, &pubKeyRaw, &privKeyRaw, nil
}
