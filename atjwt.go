package atjwt

import (
	"crypto/ecdsa"
	"time"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-didkey"
	"github.com/reiver/go-jwt"
)

// VerifyWithDIDKey verifies a JWT's signature with an ATProto key (ex: from a DID document's "#atproto" verification method),
// following ATProto's rules:
//
//	• the token's "alg" must be the key's ("ES256" for P-256, "ES256K" for secp256k1),
//	• the signature must be r‖s with a low s.
//
// Only P-256 is supported (secp256k1 keys give [ErrUnsupportedKeyType]).
// It does not check the claims.
func VerifyWithDIDKey(token string, key didkey.PublicKey) (jwt.Token, error) {
	verifier, err := verifierFor(key)
	if nil != err {
		return jwt.Token{}, err
	}

	verified, err := jwt.Verify(token, verifier)
	if nil != err {
		return jwt.Token{}, erorr.Wrap(ErrBadJWTSignature, "token signature not verified", field.Error("error", err))
	}
	return verified, nil
}

func verifierFor(key didkey.PublicKey) (jwt.Verifier, error) {
	switch key.Type() {
	case didkey.KeyTypeP256:
		publicKey, err := key.ECDSA()
		if nil != err {
			return nil, err
		}
		return jwt.ES256Verifier{Key: publicKey, RequireLowS: true}, nil
	case "":
		return nil, ErrNilKey
	default:
		return nil, erorr.Wrap(ErrUnsupportedKeyType, "unsupported key type", field.String("key-type", string(key.Type())))
	}
}

// signerFor returns the signer for a P-256 private key. (Its signatures have a low s, as ATProto requires.)
func signerFor(key *ecdsa.PrivateKey) (jwt.Signer, error) {
	if nil == key {
		return nil, ErrNilKey
	}
	if _, err := didkey.FromECDSA(&key.PublicKey); nil != err {
		return nil, erorr.Wrap(ErrUnsupportedKeyType, "not a P-256 key", field.Error("error", err))
	}
	return jwt.ES256Signer{Key: key}, nil
}

func nowOr(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now()
	}
	return now
}
