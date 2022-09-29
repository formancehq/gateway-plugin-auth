package gateway_plugin_auth

import (
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

const (
	//BearerToken defines the token_type `Bearer`, which is returned in a successful token response.
	BearerToken = "Bearer"

	PrefixBearer = BearerToken + " "
)

type Tokens struct {
	*oauth2.Token
	IDTokenClaims IDTokenClaims
	IDToken       string
}

type AccessTokenClaims interface {
	Claims
	GetSubject() string
	GetTokenID() string
	SetPrivateClaims(map[string]interface{})
}

type IDTokenClaims interface {
	Claims
	GetNotBefore() time.Time
	GetJWTID() string
	GetAccessTokenHash() string
	GetCodeHash() string
	GetAuthenticationMethodsReferences() []string
	GetClientID() string
	GetSignatureAlgorithm() SignatureAlgorithm
	SetAccessTokenHash(hash string)
	SetCodeHash(hash string)
}

func EmptyAccessTokenClaims() AccessTokenClaims {
	return new(accessTokenClaims)
}

type accessTokenClaims struct {
	Issuer                              string   `json:"iss,omitempty"`
	Subject                             string   `json:"sub,omitempty"`
	Audience                            Audience `json:"aud,omitempty"`
	Expiration                          Time     `json:"exp,omitempty"`
	IssuedAt                            Time     `json:"iat,omitempty"`
	NotBefore                           Time     `json:"nbf,omitempty"`
	JWTID                               string   `json:"jti,omitempty"`
	AuthorizedParty                     string   `json:"azp,omitempty"`
	Nonce                               string   `json:"nonce,omitempty"`
	AuthTime                            Time     `json:"auth_time,omitempty"`
	CodeHash                            string   `json:"c_hash,omitempty"`
	AuthenticationContextClassReference string   `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string `json:"amr,omitempty"`
	SessionID                           string   `json:"sid,omitempty"`
	Scopes                              []string `json:"scope,omitempty"`
	ClientID                            string   `json:"client_id,omitempty"`
	AccessTokenUseNumber                int      `json:"at_use_nbr,omitempty"`

	claims       map[string]interface{} `json:"-"`
	signatureAlg SignatureAlgorithm     `json:"-"`
}

// GetIssuer implements the Claims interface.
func (a *accessTokenClaims) GetIssuer() string {
	return a.Issuer
}

// GetAudience implements the Claims interface.
func (a *accessTokenClaims) GetAudience() []string {
	return a.Audience
}

// GetExpiration implements the Claims interface.
func (a *accessTokenClaims) GetExpiration() time.Time {
	return time.Time(a.Expiration)
}

// GetIssuedAt implements the Claims interface.
func (a *accessTokenClaims) GetIssuedAt() time.Time {
	return time.Time(a.IssuedAt)
}

// GetNonce implements the Claims interface.
func (a *accessTokenClaims) GetNonce() string {
	return a.Nonce
}

// GetAuthenticationContextClassReference implements the Claims interface.
func (a *accessTokenClaims) GetAuthenticationContextClassReference() string {
	return a.AuthenticationContextClassReference
}

// GetAuthTime implements the Claims interface.
func (a *accessTokenClaims) GetAuthTime() time.Time {
	return time.Time(a.AuthTime)
}

// GetAuthorizedParty implements the Claims interface.
func (a *accessTokenClaims) GetAuthorizedParty() string {
	return a.AuthorizedParty
}

// SetSignatureAlgorithm implements the Claims interface.
func (a *accessTokenClaims) SetSignatureAlgorithm(algorithm SignatureAlgorithm) {
	a.signatureAlg = algorithm
}

// GetSubject implements the AccessTokenClaims interface.
func (a *accessTokenClaims) GetSubject() string {
	return a.Subject
}

// GetTokenID implements the AccessTokenClaims interface.
func (a *accessTokenClaims) GetTokenID() string {
	return a.JWTID
}

// SetPrivateClaims implements the AccessTokenClaims interface.
func (a *accessTokenClaims) SetPrivateClaims(claims map[string]interface{}) {
	a.claims = claims
}

func (a *accessTokenClaims) MarshalJSON() ([]byte, error) {
	type Alias accessTokenClaims
	s := &struct {
		*Alias
		Expiration int64 `json:"exp,omitempty"`
		IssuedAt   int64 `json:"iat,omitempty"`
		NotBefore  int64 `json:"nbf,omitempty"`
		AuthTime   int64 `json:"auth_time,omitempty"`
	}{
		Alias: (*Alias)(a),
	}
	if !time.Time(a.Expiration).IsZero() {
		s.Expiration = time.Time(a.Expiration).Unix()
	}
	if !time.Time(a.IssuedAt).IsZero() {
		s.IssuedAt = time.Time(a.IssuedAt).Unix()
	}
	if !time.Time(a.NotBefore).IsZero() {
		s.NotBefore = time.Time(a.NotBefore).Unix()
	}
	if !time.Time(a.AuthTime).IsZero() {
		s.AuthTime = time.Time(a.AuthTime).Unix()
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	if a.claims == nil {
		return b, nil
	}
	info, err := json.Marshal(a.claims)
	if err != nil {
		return nil, err
	}
	return ConcatenateJSON(b, info)
}

func (a *accessTokenClaims) UnmarshalJSON(data []byte) error {
	type Alias accessTokenClaims
	if err := json.Unmarshal(data, (*Alias)(a)); err != nil {
		return err
	}
	claims := make(map[string]interface{})
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}
	a.claims = claims

	return nil
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
	State        string `json:"state,omitempty" schema:"state,omitempty"`
}
