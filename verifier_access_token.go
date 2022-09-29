package gateway_plugin_auth

import (
	"context"
	"time"
)

type AccessTokenVerifier interface {
	Verifier
	SupportedSignAlgs() []string
	KeySet() KeySet
}

type accessTokenVerifier struct {
	issuer            string
	maxAgeIAT         time.Duration
	offset            time.Duration
	supportedSignAlgs []string
	keySet            KeySet
}

// Issuer implements oidc.Verifier interface
func (i *accessTokenVerifier) Issuer() string {
	return i.issuer
}

// MaxAgeIAT implements oidc.Verifier interface
func (i *accessTokenVerifier) MaxAgeIAT() time.Duration {
	return i.maxAgeIAT
}

// Offset implements oidc.Verifier interface
func (i *accessTokenVerifier) Offset() time.Duration {
	return i.offset
}

// SupportedSignAlgs implements AccessTokenVerifier interface
func (i *accessTokenVerifier) SupportedSignAlgs() []string {
	return i.supportedSignAlgs
}

// KeySet implements AccessTokenVerifier interface
func (i *accessTokenVerifier) KeySet() KeySet {
	return i.keySet
}

func NewAccessTokenVerifier(issuer string, keySet KeySet) AccessTokenVerifier {
	verifier := &accessTokenVerifier{
		issuer: issuer,
		keySet: keySet,
	}
	return verifier
}

// VerifyAccessToken validates the access token (issuer, signature and expiration)
func VerifyAccessToken(ctx context.Context, token string, v AccessTokenVerifier) (AccessTokenClaims, error) {
	claims := EmptyAccessTokenClaims()

	decrypted, err := DecryptToken(token)
	if err != nil {
		return nil, err
	}
	payload, err := ParseToken(decrypted, claims)
	if err != nil {
		return nil, err
	}

	if err := CheckIssuer(claims, v.Issuer()); err != nil {
		return nil, err
	}

	if err = CheckSignature(ctx, decrypted, payload, claims, v.SupportedSignAlgs(), v.KeySet()); err != nil {
		return nil, err
	}

	if err = CheckExpiration(claims, v.Offset()); err != nil {
		return nil, err
	}

	return claims, nil
}
