package atjwt

import (
	"codeberg.org/reiver/go-erorr"
)

// The errors are named after the XRPC error names a space host answers with (ex: ErrBadJWTAudience ↔ "BadJwtAudience").
const (
	ErrBadJWT             = erorr.Error("atjwt: BadJwt — bad token")
	ErrBadJWTAudience     = erorr.Error("atjwt: BadJwtAudience — bad or wrong \"aud\"")
	ErrBadJWTCnf          = erorr.Error("atjwt: BadJwtCnf — bad or missing \"cnf.kid\"")
	ErrBadJWTIss          = erorr.Error("atjwt: BadJwtIss — bad or missing \"iss\"")
	ErrBadJWTSignature    = erorr.Error("atjwt: BadJwtSignature — bad signature")
	ErrBadJWTSub          = erorr.Error("atjwt: BadJwtSub — bad or wrong \"sub\"")
	ErrBadJWTType         = erorr.Error("atjwt: BadJwtType — wrong \"typ\"")
	ErrJWTExpired         = erorr.Error("atjwt: JwtExpired — token expired")
	ErrNilKey             = erorr.Error("atjwt: nil key")
	ErrUnsupportedKeyType = erorr.Error("atjwt: unsupported key type — only P-256 (ES256) is supported")
)
