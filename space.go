package atjwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"

	"codeberg.org/reiver/go-erorr"
	"codeberg.org/reiver/go-field"
	"github.com/reiver/go-didkey"
	"github.com/reiver/go-jwt"
)

// The "typ" header parameters of the space tokens.
const (
	TypDelegationToken   = "atproto-space-delegation+jwt"
	TypSpaceCredential   = "atproto-space-credential+jwt"
	TypClientAttestation = "atproto-client-attestation+jwt"
)

// KidAtproto is the "kid" of tokens signed with an account's "#atproto" key.
const KidAtproto = "#atproto"

const (
	// ClockSkew is how much clock difference is allowed when checking "iat" and "exp".
	ClockSkew = 5 * time.Second

	// SpaceCredentialMaxAge is the longest a space credential may be valid for ("exp" − "iat").
	SpaceCredentialMaxAge = time.Hour
)

// SpaceTokenType is one of the kinds of space token.
type SpaceTokenType int

const (
	// DelegationToken is a user's (or a bot's) authorization for an app to get a space credential on its behalf.
	// Signed with the issuer's "#atproto" key.
	DelegationToken SpaceTokenType = iota + 1

	// SpaceCredential is a space authority's grant to read a space, bound (by "cnf.kid") to the holder's key.
	// Signed with the authority's "#atproto" key.
	SpaceCredential

	// ClientAttestation is an OAuth client's proof of identity to a space host. Signed with a key from the client's JWKS.
	ClientAttestation
)

type spaceTokenSpec struct {
	typ        string
	kid        string // if not empty, the header's "kid" must be this
	expiresIn  time.Duration
	requireAud bool
	requireCnf bool
}

func (receiver SpaceTokenType) spec() (spaceTokenSpec, bool) {
	switch receiver {
	case DelegationToken:
		return spaceTokenSpec{typ: TypDelegationToken, kid: KidAtproto, expiresIn: 60 * time.Second, requireAud: true}, true
	case SpaceCredential:
		return spaceTokenSpec{typ: TypSpaceCredential, kid: KidAtproto, expiresIn: 600 * time.Second, requireCnf: true}, true
	case ClientAttestation:
		return spaceTokenSpec{typ: TypClientAttestation, expiresIn: 60 * time.Second, requireAud: true}, true
	default:
		return spaceTokenSpec{}, false
	}
}

// SpaceHostAud returns the audience of delegation tokens and client attestations for a space whose authority is 'authorityDID':
// the authority's "#atproto_pds" service (ex: "did:plc:abc#atproto_pds").
func SpaceHostAud(authorityDID string) string {
	return authorityDID + "#atproto_pds"
}

// SpaceToken is a parsed space token.
type SpaceToken struct {
	Type   SpaceTokenType
	Header jwt.Header
	Claims jwt.Claims

	Issuer   string
	Subject  string    // the space URI — or, for a client attestation, the client_id
	Audience string    // not in a space credential
	KeyID    string    // "cnf.kid" — only in a space credential: the did:key the holder signs requests with
	IssuedAt time.Time // the zero time if absent
	Expires  time.Time
	JWTID    string

	token string
}

var didRegexp = regexp.MustCompile(`^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$`)

// ParseSpaceToken parses a space token of the kind 'tokenType', and checks its structure — WITHOUT verifying its signature
// (see [VerifySpaceToken]). For example, a space credential's holder uses it to read the credential's "exp".
//
// It checks: the "typ"; a non-empty "alg"; the "kid" (for delegation tokens and space credentials: "#atproto");
// non-empty "iss", "sub", and "jti"; an "exp"; an "aud" (for delegation tokens and client attestations);
// a DID "cnf.kid" (for space credentials); a lifetime of at most [SpaceCredentialMaxAge] (for space credentials);
// and "iss" = "sub" (for client attestations).
func ParseSpaceToken(tokenType SpaceTokenType, token string) (SpaceToken, error) {
	spec, found := tokenType.spec()
	if !found {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "unknown space token type", field.Int("type", int(tokenType)))
	}

	parsed, err := jwt.Parse(token)
	if nil != err {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "malformed token", field.Error("error", err))
	}

	if typ := parsed.Header.Typ(); spec.typ != typ {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTType, "wrong token type", field.String("typ", typ), field.String("expected", spec.typ))
	}
	if "" == parsed.Header.Alg() {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "missing token \"alg\"")
	}
	if "" != spec.kid && spec.kid != parsed.Header.Kid() {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "wrong token \"kid\"", field.String("kid", parsed.Header.Kid()), field.String("expected", spec.kid))
	}

	var result SpaceToken = SpaceToken{Type: tokenType, Header: parsed.Header, Claims: parsed.Claims, token: token}

	result.Issuer, _ = parsed.Claims.Issuer()
	if "" == result.Issuer {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTIss, "missing token \"iss\"")
	}
	result.Subject, _ = parsed.Claims.Subject()
	if "" == result.Subject {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTSub, "missing token \"sub\"")
	}

	expires, found := parsed.Claims.ExpiresAt()
	if !found {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "missing token \"exp\"")
	}
	result.Expires = expires
	result.IssuedAt, _ = parsed.Claims.IssuedAt()

	if aud, casted := parsed.Claims["aud"].(string); casted {
		result.Audience = aud
	}
	if spec.requireAud && "" == result.Audience {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTAudience, "missing token \"aud\"")
	}

	if cnf, casted := parsed.Claims["cnf"].(map[string]any); casted {
		result.KeyID, _ = cnf["kid"].(string)
	}
	if spec.requireCnf && !didRegexp.MatchString(result.KeyID) {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTCnf, "missing token \"cnf.kid\"")
	}

	result.JWTID, _ = parsed.Claims.JWTID()
	if "" == result.JWTID {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "missing token \"jti\"")
	}

	if SpaceCredential == tokenType {
		if _, found := parsed.Claims.IssuedAt(); !found {
			return SpaceToken{}, erorr.Wrap(ErrBadJWT, "missing space credential \"iat\"")
		}
		if lifetime := result.Expires.Sub(result.IssuedAt); lifetime <= 0 || SpaceCredentialMaxAge < lifetime {
			return SpaceToken{}, erorr.Wrap(ErrBadJWT, "invalid space credential lifetime", field.String("lifetime", lifetime.String()))
		}
	}
	if ClientAttestation == tokenType && result.Issuer != result.Subject {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTIss, "client attestation \"iss\" and \"sub\" must both be the client_id")
	}

	return result, nil
}

// VerifyOptions are what [VerifySpaceToken] checks a space token against.
type VerifyOptions struct {
	// Key is the issuer's "#atproto" key. (Resolving the issuer's DID document — and re-resolving it, if the key may have rotated — is up to the caller.)
	Key didkey.PublicKey

	// Audience, if not empty, must be the token's "aud".
	Audience string

	// Subject, if not empty, must be the token's "sub".
	Subject string

	// Now is the current time. (The zero value means time.Now().)
	Now time.Time
}

// VerifySpaceToken parses a space token (see [ParseSpaceToken]), checks its times, audience, and subject, and verifies its signature (see [VerifyWithDIDKey]).
//
// The token is expired if now − [ClockSkew] ≥ "exp". A space credential issued after now + [ClockSkew] is rejected.
//
// (Client attestations are signed with a key from the client's JWKS, not a DID document — so verify them with [jwt.Verify] instead.)
func VerifySpaceToken(tokenType SpaceTokenType, token string, options VerifyOptions) (SpaceToken, error) {
	parsed, err := ParseSpaceToken(tokenType, token)
	if nil != err {
		return SpaceToken{}, err
	}

	var now time.Time = nowOr(options.Now)
	if SpaceCredential == tokenType && parsed.IssuedAt.After(now.Add(ClockSkew)) {
		return SpaceToken{}, erorr.Wrap(ErrBadJWT, "space credential issued in the future")
	}
	if !now.Add(-ClockSkew).Before(parsed.Expires) {
		return SpaceToken{}, erorr.Wrap(ErrJWTExpired, "token expired", field.String("exp", parsed.Expires.Format(time.RFC3339)))
	}
	if "" != options.Audience && options.Audience != parsed.Audience {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTAudience, "token audience does not match", field.String("aud", parsed.Audience), field.String("expected", options.Audience))
	}
	if "" != options.Subject && options.Subject != parsed.Subject {
		return SpaceToken{}, erorr.Wrap(ErrBadJWTSub, "token subject does not match", field.String("sub", parsed.Subject), field.String("expected", options.Subject))
	}

	if _, err := VerifyWithDIDKey(token, options.Key); nil != err {
		return SpaceToken{}, err
	}

	return parsed, nil
}

// String returns the token, as it was parsed.
func (receiver SpaceToken) String() string {
	return receiver.token
}

// NewSpaceToken holds what is needed to make a space token. The "iat", "exp", and "jti" are filled in when it is signed.
type NewSpaceToken struct {
	Issuer   string
	Subject  string
	Audience string // for delegation tokens and client attestations
	KeyID    string // "cnf.kid" — for space credentials: the holder's did:key
	Kid      string // the header's "kid" — for client attestations (delegation tokens and space credentials always use "#atproto")

	// ExpiresIn is the token's lifetime. Zero means the default: 60 seconds for delegation tokens and client attestations, 600 seconds for space credentials.
	ExpiresIn time.Duration

	// Now is the issue time ("iat"). The zero value means time.Now().
	Now time.Time

	// JWTID is the "jti". Empty means a new random one (16 random bytes, in hex).
	JWTID string
}

// SignSpaceToken makes a space token of the kind 'tokenType', signed with the P-256 key 'key' (ES256, with a low s).
//
// Example usage (a bot's delegation token):
//
//	token, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{
//		Issuer:   botDID,
//		Subject:  spaceURI,
//		Audience: atjwt.SpaceHostAud(authorityDID),
//	}, atprotoKey)
func SignSpaceToken(tokenType SpaceTokenType, token NewSpaceToken, key *ecdsa.PrivateKey) (string, error) {
	spec, found := tokenType.spec()
	if !found {
		return "", erorr.Wrap(ErrBadJWT, "unknown space token type", field.Int("type", int(tokenType)))
	}

	signer, err := signerFor(key)
	if nil != err {
		return "", err
	}

	var header jwt.Header = jwt.Header{"typ": spec.typ}
	switch {
	case "" != spec.kid:
		header["kid"] = spec.kid
	case "" != token.Kid:
		header["kid"] = token.Kid
	}

	var expiresIn time.Duration = token.ExpiresIn
	if 0 == expiresIn {
		expiresIn = spec.expiresIn
	}
	if expiresIn < time.Second || (SpaceCredential == tokenType && SpaceCredentialMaxAge < expiresIn) {
		return "", erorr.Wrap(ErrBadJWT, "invalid token lifetime", field.String("expires-in", expiresIn.String()))
	}

	var jti string = token.JWTID
	if "" == jti {
		var random [16]byte
		if _, err := rand.Read(random[:]); nil != err {
			return "", err
		}
		jti = hex.EncodeToString(random[:])
	}

	var iat int64 = nowOr(token.Now).Unix()
	var claims jwt.Claims = jwt.Claims{
		"iss": token.Issuer,
		"sub": token.Subject,
		"iat": iat,
		"exp": iat + int64(expiresIn/time.Second),
		"jti": jti,
	}
	if "" != token.Audience {
		claims["aud"] = token.Audience
	}
	if "" != token.KeyID {
		claims["cnf"] = map[string]any{"kid": token.KeyID}
	}

	signed, err := jwt.Sign(header, claims, signer)
	if nil != err {
		return "", err
	}

	// Check what was made, as a receiver would.
	if _, err := ParseSpaceToken(tokenType, signed); nil != err {
		return "", err
	}
	return signed, nil
}
