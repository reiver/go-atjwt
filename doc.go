/*
Package atjwt implements ATProto's JSON Web Tokens — ATProto's rules on top of github.com/reiver/go-jwt, and the space tokens — for the Go programming language.

# ATProto's rules

	• Keys are ATProto keys — did:key / Multikey (see github.com/reiver/go-didkey).
	• The "alg" must match the key: "ES256" for P-256, "ES256K" for secp256k1.
	• Signatures are r‖s, with a low s (a high s is rejected).

[VerifyWithDIDKey] verifies a token by these rules. Only P-256 is supported for now (Go's standard library has no secp256k1).

# Space tokens

	┌─────────────────────┬────────────────────────────────┬────────────┬─────────────────┬──────────────────────────────────┐
	│ kind                │ "typ"                          │ "kid"      │ default lifetime│ claims                           │
	├─────────────────────┼────────────────────────────────┼────────────┼─────────────────┼──────────────────────────────────┤
	│ [DelegationToken]   │ atproto-space-delegation+jwt   │ #atproto   │ 60 s            │ iss, sub (space), aud, iat, exp, │
	│                     │                                │            │                 │ jti                              │
	│ [SpaceCredential]   │ atproto-space-credential+jwt   │ #atproto   │ 600 s (≤ 1 h)   │ iss, sub (space), cnf.kid, iat,  │
	│                     │                                │            │                 │ exp, jti                         │
	│ [ClientAttestation] │ atproto-client-attestation+jwt │ (any)      │ 60 s            │ iss = sub = client_id, aud, iat, │
	│                     │                                │            │                 │ exp, jti                         │
	└─────────────────────┴────────────────────────────────┴────────────┴─────────────────┴──────────────────────────────────┘

The "aud" of delegation tokens and client attestations is the space authority's "#atproto_pds" service — see [SpaceHostAud].

[SignSpaceToken] makes one; [ParseSpaceToken] reads one without verifying it; [VerifySpaceToken] verifies one.
Clocks may differ by up to [ClockSkew].

# Example

	// A bot's delegation token:
	token, err := atjwt.SignSpaceToken(atjwt.DelegationToken, atjwt.NewSpaceToken{
		Issuer:   botDID,
		Subject:  spaceURI,
		Audience: atjwt.SpaceHostAud(authorityDID),
	}, atprotoKey)

	// Reading the space credential it gets back (the space host verifies it; the holder just needs its "exp"):
	credential, err := atjwt.ParseSpaceToken(atjwt.SpaceCredential, s)
	renewBy := credential.Expires
*/
package atjwt
