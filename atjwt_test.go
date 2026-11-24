package atjwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/reiver/go-didkey"
	"github.com/reiver/go-jwt"

	"github.com/reiver/go-atjwt"
)

const (
	botDID       = "did:web:mirror.example.com"
	authorityDID = "did:plc:authority"
	spaceURI     = "at://did:plc:authority/space/app.bsky.group/test"
	clientID     = "https://app.example.com/client-metadata.json"
)

var issued = time.Unix(1795500000, 0)

func newKey(t *testing.T) (*ecdsa.PrivateKey, didkey.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	public, err := didkey.FromECDSA(&key.PublicKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return key, public
}

// decodePart returns a token part's JSON.
func decodePart(t *testing.T, token string, index int) string {
	t.Helper()

	p, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[index])
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return string(p)
}

func TestDelegationToken(t *testing.T) {
	key, public := newKey(t)

	token, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{
		Issuer:   botDID,
		Subject:  spaceURI,
		Audience: atjwt.SpaceHostAud(authorityDID),
		Now:      issued,
		JWTID:    "0123456789abcdef0123456789abcdef",
	}, key)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	if expected := `{"alg":"ES256","kid":"#atproto","typ":"atproto-space-delegation+jwt"}`; expected != decodePart(t, token, 0) {
		t.Errorf("Expected header %s but actually got %s.", expected, decodePart(t, token, 0))
	}
	if expected := `{"aud":"did:plc:authority#atproto_pds","exp":1795500060,"iat":1795500000,"iss":"did:web:mirror.example.com","jti":"0123456789abcdef0123456789abcdef","sub":"at://did:plc:authority/space/app.bsky.group/test"}`; expected != decodePart(t, token, 1) {
		t.Errorf("Expected claims %s but actually got %s.", expected, decodePart(t, token, 1))
	}

	verified, err := atjwt.VerifySpaceToken(atjwt.DelegationToken, token, atjwt.VerifyOptions{
		Key:      public,
		Audience: "did:plc:authority#atproto_pds",
		Subject:  spaceURI,
		Now:      issued.Add(30 * time.Second),
	})
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if botDID != verified.Issuer || spaceURI != verified.Subject || 1795500060 != verified.Expires.Unix() || token != verified.String() {
		t.Errorf("Unexpected token %#v.", verified)
	}

	tests := []struct {
		Name     string
		Options  atjwt.VerifyOptions
		Expected error
	}{
		{Name: "expired", Options: atjwt.VerifyOptions{Key: public, Now: issued.Add(65 * time.Second)}, Expected: atjwt.ErrJWTExpired},
		{Name: "within the clock skew", Options: atjwt.VerifyOptions{Key: public, Now: issued.Add(64 * time.Second)}, Expected: nil},
		{Name: "another audience", Options: atjwt.VerifyOptions{Key: public, Audience: "did:plc:other#atproto_pds", Now: issued}, Expected: atjwt.ErrBadJWTAudience},
		{Name: "another subject", Options: atjwt.VerifyOptions{Key: public, Subject: "at://did:plc:other/space/x/y", Now: issued}, Expected: atjwt.ErrBadJWTSub},
		{Name: "no key", Options: atjwt.VerifyOptions{Now: issued}, Expected: atjwt.ErrNilKey},
	}
	for _, test := range tests {
		_, err := atjwt.VerifySpaceToken(atjwt.DelegationToken, token, test.Options)
		if !errors.Is(err, test.Expected) || (nil == test.Expected && nil != err) {
			t.Errorf("For %q, expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	// Another key does not verify it.
	_, other := newKey(t)
	if _, err := atjwt.VerifySpaceToken(atjwt.DelegationToken, token, atjwt.VerifyOptions{Key: other, Now: issued}); !errors.Is(err, atjwt.ErrBadJWTSignature) {
		t.Errorf("Expected ErrBadJWTSignature but actually got: %v", err)
	}

	// It is not a space credential.
	if _, err := atjwt.ParseSpaceToken(atjwt.SpaceCredential, token); !errors.Is(err, atjwt.ErrBadJWTType) {
		t.Errorf("Expected ErrBadJWTType but actually got: %v", err)
	}
}

func TestDelegationToken_randomJTI(t *testing.T) {
	key, _ := newKey(t)

	var seen map[string]bool = map[string]bool{}
	for range 4 {
		token, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{Issuer: botDID, Subject: spaceURI, Audience: atjwt.SpaceHostAud(authorityDID)}, key)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		parsed, err := atjwt.ParseSpaceToken(atjwt.DelegationToken, token)
		if nil != err {
			t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
		}
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(parsed.JWTID) || seen[parsed.JWTID] {
			t.Errorf("Expected a new 32-hex-digit jti, but actually got %q.", parsed.JWTID)
		}
		seen[parsed.JWTID] = true

		// The default "now" is the current time.
		if d := time.Since(parsed.IssuedAt); d < -time.Second || time.Minute < d {
			t.Errorf("Unexpected iat %v.", parsed.IssuedAt)
		}
	}
}

func TestSpaceCredential(t *testing.T) {
	authorityKey, authorityPublic := newKey(t)
	_, holderPublic := newKey(t)

	token, err := atjwt.SignSpaceToken(atjwt.SpaceCredential, atjwt.NewSpaceToken{
		Issuer:  authorityDID,
		Subject: spaceURI,
		KeyID:   holderPublic.DIDKey(),
		Now:     issued,
	}, authorityKey)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	if expected := `{"alg":"ES256","kid":"#atproto","typ":"atproto-space-credential+jwt"}`; expected != decodePart(t, token, 0) {
		t.Errorf("Expected header %s but actually got %s.", expected, decodePart(t, token, 0))
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(decodePart(t, token, 1)), &claims); nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if _, found := claims["aud"]; found {
		t.Error("A space credential has no aud.")
	}
	if float64(1795500600) != claims["exp"] {
		t.Errorf("Expected exp = iat + 600 but actually got %v.", claims["exp"])
	}

	// The holder reads it without verifying it.
	parsed, err := atjwt.ParseSpaceToken(atjwt.SpaceCredential, token)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if holderPublic.DIDKey() != parsed.KeyID || 1795500600 != parsed.Expires.Unix() || "" == parsed.JWTID {
		t.Errorf("Unexpected credential %#v.", parsed)
	}

	// A host verifies it.
	if _, err := atjwt.VerifySpaceToken(atjwt.SpaceCredential, token, atjwt.VerifyOptions{Key: authorityPublic, Subject: spaceURI, Now: issued}); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	// Issued in the future (beyond the clock skew).
	if _, err := atjwt.VerifySpaceToken(atjwt.SpaceCredential, token, atjwt.VerifyOptions{Key: authorityPublic, Now: issued.Add(-6 * time.Second)}); !errors.Is(err, atjwt.ErrBadJWT) {
		t.Errorf("Expected ErrBadJWT but actually got: %v", err)
	}

	// The lifetime is at most an hour.
	if _, err := atjwt.SignSpaceToken(atjwt.SpaceCredential, atjwt.NewSpaceToken{Issuer: authorityDID, Subject: spaceURI, KeyID: holderPublic.DIDKey(), ExpiresIn: time.Hour + time.Second}, authorityKey); !errors.Is(err, atjwt.ErrBadJWT) {
		t.Errorf("Expected ErrBadJWT but actually got: %v", err)
	}
	if _, err := atjwt.SignSpaceToken(atjwt.SpaceCredential, atjwt.NewSpaceToken{Issuer: authorityDID, Subject: spaceURI, KeyID: holderPublic.DIDKey(), ExpiresIn: time.Hour}, authorityKey); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// cnf.kid is required.
	if _, err := atjwt.SignSpaceToken(atjwt.SpaceCredential, atjwt.NewSpaceToken{Issuer: authorityDID, Subject: spaceURI}, authorityKey); !errors.Is(err, atjwt.ErrBadJWTCnf) {
		t.Errorf("Expected ErrBadJWTCnf but actually got: %v", err)
	}
}

func TestClientAttestation(t *testing.T) {
	key, _ := newKey(t)

	token, err := atjwt.SignSpaceToken(atjwt.ClientAttestation, atjwt.NewSpaceToken{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: atjwt.SpaceHostAud(authorityDID),
		Kid:      "attestation-key-1",
		Now:      issued,
	}, key)
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if expected := `{"alg":"ES256","kid":"attestation-key-1","typ":"atproto-client-attestation+jwt"}`; expected != decodePart(t, token, 0) {
		t.Errorf("Expected header %s but actually got %s.", expected, decodePart(t, token, 0))
	}

	// Its key is in the client's JWKS — so it is verified with go-jwt (with low s required, as ATProto does).
	if _, err := jwt.Verify(token, jwt.ES256Verifier{Key: &key.PublicKey, RequireLowS: true}); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// iss and sub must both be the client_id.
	if _, err := atjwt.SignSpaceToken(atjwt.ClientAttestation, atjwt.NewSpaceToken{Issuer: clientID, Subject: "https://other.example.com", Audience: "x"}, key); !errors.Is(err, atjwt.ErrBadJWTIss) {
		t.Errorf("Expected ErrBadJWTIss but actually got: %v", err)
	}
	// aud is required.
	if _, err := atjwt.SignSpaceToken(atjwt.ClientAttestation, atjwt.NewSpaceToken{Issuer: clientID, Subject: clientID}, key); !errors.Is(err, atjwt.ErrBadJWTAudience) {
		t.Errorf("Expected ErrBadJWTAudience but actually got: %v", err)
	}
}

// rawToken signs any header and claims (so tests can make tokens SignSpaceToken would refuse to).
func rawToken(t *testing.T, key *ecdsa.PrivateKey, header jwt.Header, claims jwt.Claims) string {
	t.Helper()

	token, err := jwt.Sign(header, claims, jwt.ES256Signer{Key: key})
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	return token
}

func TestParseSpaceToken_errors(t *testing.T) {
	key, _ := newKey(t)

	delegationHeader := func() jwt.Header {
		return jwt.Header{"typ": atjwt.TypDelegationToken, "kid": "#atproto"}
	}
	delegationClaims := func() jwt.Claims {
		return jwt.Claims{"iss": botDID, "sub": spaceURI, "aud": "x", "iat": 1, "exp": 61, "jti": "j"}
	}
	without := func(claims jwt.Claims, name string) jwt.Claims {
		delete(claims, name)
		return claims
	}
	with := func(claims jwt.Claims, name string, value any) jwt.Claims {
		claims[name] = value
		return claims
	}

	credentialHeader := jwt.Header{"typ": atjwt.TypSpaceCredential, "kid": "#atproto"}
	credentialClaims := func() jwt.Claims {
		return jwt.Claims{"iss": authorityDID, "sub": spaceURI, "iat": 1000, "exp": 1600, "jti": "j", "cnf": map[string]any{"kid": "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"}}
	}

	tests := []struct {
		Name     string
		Type     atjwt.SpaceTokenType
		Token    string
		Expected error
	}{
		{Name: "malformed", Type: atjwt.DelegationToken, Token: "nope", Expected: atjwt.ErrBadJWT},
		{Name: "no typ", Type: atjwt.DelegationToken, Token: rawToken(t, key, jwt.Header{"kid": "#atproto"}, delegationClaims()), Expected: atjwt.ErrBadJWTType},
		{Name: "typ in another case", Type: atjwt.DelegationToken, Token: rawToken(t, key, jwt.Header{"typ": "ATPROTO-SPACE-DELEGATION+JWT", "kid": "#atproto"}, delegationClaims()), Expected: atjwt.ErrBadJWTType},
		{Name: "no kid", Type: atjwt.DelegationToken, Token: rawToken(t, key, jwt.Header{"typ": atjwt.TypDelegationToken}, delegationClaims()), Expected: atjwt.ErrBadJWT},
		{Name: "another kid", Type: atjwt.DelegationToken, Token: rawToken(t, key, jwt.Header{"typ": atjwt.TypDelegationToken, "kid": "#other"}, delegationClaims()), Expected: atjwt.ErrBadJWT},
		{Name: "no iss", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), without(delegationClaims(), "iss")), Expected: atjwt.ErrBadJWTIss},
		{Name: "empty iss", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), with(delegationClaims(), "iss", "")), Expected: atjwt.ErrBadJWTIss},
		{Name: "no sub", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), without(delegationClaims(), "sub")), Expected: atjwt.ErrBadJWTSub},
		{Name: "no exp", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), without(delegationClaims(), "exp")), Expected: atjwt.ErrBadJWT},
		{Name: "no aud", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), without(delegationClaims(), "aud")), Expected: atjwt.ErrBadJWTAudience},
		{Name: "aud an array", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), with(delegationClaims(), "aud", []string{"x"})), Expected: atjwt.ErrBadJWTAudience},
		{Name: "no jti", Type: atjwt.DelegationToken, Token: rawToken(t, key, delegationHeader(), without(delegationClaims(), "jti")), Expected: atjwt.ErrBadJWT},
		{Name: "credential: no cnf", Type: atjwt.SpaceCredential, Token: rawToken(t, key, credentialHeader, without(credentialClaims(), "cnf")), Expected: atjwt.ErrBadJWTCnf},
		{Name: "credential: cnf.kid not a DID", Type: atjwt.SpaceCredential, Token: rawToken(t, key, credentialHeader, with(credentialClaims(), "cnf", map[string]any{"kid": "#atproto"})), Expected: atjwt.ErrBadJWTCnf},
		{Name: "credential: no iat", Type: atjwt.SpaceCredential, Token: rawToken(t, key, credentialHeader, without(credentialClaims(), "iat")), Expected: atjwt.ErrBadJWT},
		{Name: "credential: exp = iat", Type: atjwt.SpaceCredential, Token: rawToken(t, key, credentialHeader, with(credentialClaims(), "exp", 1000)), Expected: atjwt.ErrBadJWT},
		{Name: "credential: lifetime over an hour", Type: atjwt.SpaceCredential, Token: rawToken(t, key, credentialHeader, with(credentialClaims(), "exp", 1000+3601)), Expected: atjwt.ErrBadJWT},
		{Name: "unknown type", Type: atjwt.SpaceTokenType(99), Token: rawToken(t, key, delegationHeader(), delegationClaims()), Expected: atjwt.ErrBadJWT},
	}

	for _, test := range tests {
		if _, err := atjwt.ParseSpaceToken(test.Type, test.Token); !errors.Is(err, test.Expected) {
			t.Errorf("For %q, expected %v but actually got: %v", test.Name, test.Expected, err)
		}
	}

	// A lifetime of exactly an hour is fine.
	if _, err := atjwt.ParseSpaceToken(atjwt.SpaceCredential, rawToken(t, key, credentialHeader, with(credentialClaims(), "exp", 1000+3600))); nil != err {
		t.Errorf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
}

// ATProto's signature rules: low s, and an "alg" that matches the key.
func TestVerifyWithDIDKey(t *testing.T) {
	key, public := newKey(t)

	token := rawToken(t, key, jwt.Header{"typ": "JWT"}, jwt.Claims{"iss": botDID})
	if _, err := atjwt.VerifyWithDIDKey(token, public); nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}

	// The same signature with a high s (n−s) is rejected.
	parts := strings.Split(token, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	var n *big.Int = elliptic.P256().Params().N
	high := append(append([]byte(nil), signature[:32]...), new(big.Int).Sub(n, new(big.Int).SetBytes(signature[32:])).FillBytes(make([]byte, 32))...)
	var highS string = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(high)
	if _, err := jwt.Verify(highS, jwt.ES256Verifier{Key: &key.PublicKey}); nil != err {
		t.Fatalf("Expected the high-s signature to be valid in general, but: %v", err)
	}
	if _, err := atjwt.VerifyWithDIDKey(highS, public); !errors.Is(err, atjwt.ErrBadJWTSignature) {
		t.Errorf("Expected ErrBadJWTSignature but actually got: %v", err)
	}

	// An "alg" that is not the key's.
	var es256k string = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256K"}`)) + "." + parts[1] + "." + parts[2]
	if _, err := atjwt.VerifyWithDIDKey(es256k, public); !errors.Is(err, atjwt.ErrBadJWTSignature) {
		t.Errorf("Expected ErrBadJWTSignature but actually got: %v", err)
	}

	// secp256k1 keys are not supported (yet).
	k256, err := didkey.Parse("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
	if nil != err {
		t.Fatalf("Did not expect an error but actually got one: (%T) %s", err, err)
	}
	if _, err := atjwt.VerifyWithDIDKey(token, k256); !errors.Is(err, atjwt.ErrUnsupportedKeyType) {
		t.Errorf("Expected ErrUnsupportedKeyType but actually got: %v", err)
	}

	// Signing needs a P-256 key.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{Issuer: botDID, Subject: spaceURI, Audience: "x"}, p384); !errors.Is(err, atjwt.ErrUnsupportedKeyType) {
		t.Errorf("Expected ErrUnsupportedKeyType but actually got: %v", err)
	}
	if _, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{Issuer: botDID, Subject: spaceURI, Audience: "x"}, nil); !errors.Is(err, atjwt.ErrNilKey) {
		t.Errorf("Expected ErrNilKey but actually got: %v", err)
	}
}

func TestSpaceHostAud(t *testing.T) {
	if expected, actual := "did:plc:authority#atproto_pds", atjwt.SpaceHostAud("did:plc:authority"); expected != actual {
		t.Errorf("Expected %q but actually got %q.", expected, actual)
	}
}
