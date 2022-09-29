package gateway_plugin_auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claims interface {
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	GetExpiration() time.Time
	GetIssuedAt() time.Time
	GetNonce() string
	GetAuthenticationContextClassReference() string
	GetAuthTime() time.Time
	GetAuthorizedParty() string
	ClaimsSignature
}

type ClaimsSignature interface {
	SetSignatureAlgorithm(algorithm SignatureAlgorithm)
}

var (
	ErrParse                   = errors.New("parsing of request failed")
	ErrIssuerInvalid           = errors.New("issuer does not match")
	ErrSignatureMissing        = errors.New("id_token does not contain a signature")
	ErrSignatureMultiple       = errors.New("id_token contains multiple signatures")
	ErrSignatureUnsupportedAlg = errors.New("signature algorithm not supported")
	ErrSignatureInvalidPayload = errors.New("signature does not match Payload")
	ErrSignatureInvalid        = errors.New("invalid signature")
	ErrExpired                 = errors.New("token has expired")
)

type Verifier interface {
	Issuer() string
	MaxAgeIAT() time.Duration
	Offset() time.Duration
}

// ACRVerifier specifies the function to be used by the `DefaultVerifier` for validating the acr claim.
type ACRVerifier func(string) error

func DecryptToken(tokenString string) (string, error) {
	return tokenString, nil // TODO: impl
}

func ParseToken(tokenString string, claims interface{}) ([]byte, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token contains an invalid number of segments", ErrParse)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed jwt payload: %v", ErrParse, err)
	}
	err = json.Unmarshal(payload, claims)
	return payload, err
}

func CheckIssuer(claims Claims, issuer string) error {
	if claims.GetIssuer() != issuer {
		return fmt.Errorf("%w: Expected: %s, got: %s", ErrIssuerInvalid, issuer, claims.GetIssuer())
	}
	return nil
}

func CheckSignature(ctx context.Context, token string, payload []byte, claims ClaimsSignature, supportedSigAlgs []string, set KeySet) error {
	jws, err := ParseSigned(token)
	if err != nil {
		return ErrParse
	}
	if len(jws.Signatures) == 0 {
		return ErrSignatureMissing
	}
	if len(jws.Signatures) > 1 {
		return ErrSignatureMultiple
	}
	sig := jws.Signatures[0]
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{"RS256"}
	}
	if !Contains(supportedSigAlgs, sig.Header.Algorithm) {
		return fmt.Errorf("%w: id token signed with unsupported algorithm, expected %q got %q", ErrSignatureUnsupportedAlg, supportedSigAlgs, sig.Header.Algorithm)
	}

	signedPayload, err := set.VerifySignature(ctx, jws)
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrSignatureInvalid, err)
	}

	if !bytes.Equal(signedPayload, payload) {
		return ErrSignatureInvalidPayload
	}

	return nil
}

func CheckExpiration(claims Claims, offset time.Duration) error {
	expiration := claims.GetExpiration().Round(time.Second)
	if !time.Now().UTC().Add(offset).Before(expiration) {
		return ErrExpired
	}
	return nil
}
