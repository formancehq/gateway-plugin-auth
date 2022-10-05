package gateway_plugin_auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type Config struct {
	Issuer           string
	SigningMethodRSA string
	RefreshTimeError time.Duration
	RefreshTime      time.Duration
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next             http.Handler
	issuer           string
	signingMethodRSA *jwt.SigningMethodRSA
	jwksURI          string
	publicKey        *rsa.PublicKey
	refreshTimeError time.Duration
	refreshTime      time.Duration
	initialized      chan struct{}
}

const (
	refreshTimeErrorDefault = 10 * time.Second
	refreshTimeDefault      = 15 * time.Minute
)

var (
	signingMethodDefault = jwt.SigningMethodRS256
)

func New(ctx context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	p := &Plugin{
		next:             next,
		issuer:           config.Issuer,
		refreshTimeError: config.RefreshTimeError,
		refreshTime:      config.RefreshTime,
		initialized:      make(chan struct{}),
	}

	switch config.SigningMethodRSA {
	case "":
		p.signingMethodRSA = signingMethodDefault
	case jwt.SigningMethodRS256.Alg():
		p.signingMethodRSA = jwt.SigningMethodRS256
	case jwt.SigningMethodRS384.Alg():
		p.signingMethodRSA = jwt.SigningMethodRS384
	case jwt.SigningMethodRS512.Alg():
		p.signingMethodRSA = jwt.SigningMethodRS512
	default:
		err := fmt.Errorf("ERROR: unsupported config signing method: %s", config.SigningMethodRSA)
		fmt.Println(err)
		return p, err
	}

	if p.refreshTimeError == 0 {
		p.refreshTimeError = refreshTimeErrorDefault
	}
	if p.refreshTime == 0 {
		p.refreshTime = refreshTimeDefault
	}

	go p.fetchKeys(ctx)

	return p, nil
}

func (p *Plugin) Initialized() chan struct{} {
	return p.initialized
}

func (p *Plugin) fetchKeys(ctx context.Context) {
	for {
		if err := p.fetchPublicKeys(ctx); err == nil {
			if p.initialized != nil {
				close(p.initialized)
				p.initialized = nil
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(p.refreshTime):
					continue
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.refreshTimeError):
			continue
		}
	}
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenString, err := p.extractToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	parser := new(jwt.Parser)
	token, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if token.Method.Alg() != p.signingMethodRSA.Alg() {
		http.Error(w, fmt.Errorf("unsupported token signing method: %s", token.Method.Alg()).Error(), http.StatusUnauthorized)
		return
	}

	vErr := &jwt.ValidationError{}
	token.Signature = parts[2]
	if err = verifyRSA(strings.Join(parts[0:2], "."), token.Signature, p.publicKey, p.signingMethodRSA); err != nil {
		vErr.Inner = err
		vErr.Errors |= jwt.ValidationErrorSignatureInvalid
		http.Error(w, fmt.Errorf("unverified JWT token: %w", vErr).Error(), http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(w, r)
}

func verifyRSA(signingString, signature string, rsaKey *rsa.PublicKey, m *jwt.SigningMethodRSA) error {
	var err error
	var sig []byte
	if sig, err = base64.RawURLEncoding.DecodeString(signature); err != nil {
		return err
	}

	if !m.Hash.Available() {
		return errors.New("the requested hash function is unavailable")
	}
	h := m.Hash.New()
	h.Write([]byte(signingString))

	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, h.Sum(nil), sig)
}

const (
	bearerToken       = "Bearer"
	prefixBearer      = bearerToken + " "
	discoveryEndpoint = "/.well-known/openid-configuration"
)

var (
	ErrHeaderAuthMissing   = errors.New("missing authorization header")
	ErrHeaderAuthMalformed = errors.New("malformed authorization header")
	ErrTokenInvalidFormat  = "invalid token format"
	ErrIssuerInvalid       = errors.New("issuer does not match")
)

func (p *Plugin) fetchPublicKeys(ctx context.Context) error {
	c := http.DefaultClient
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer+discoveryEndpoint, nil)
	if err != nil {
		return fmt.Errorf("new discovery request: %w", err)
	}

	response, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("get discovery: %w", err)
	}

	var cfg discoveryConfig
	if err = json.NewDecoder(response.Body).Decode(&cfg); err != nil {
		return fmt.Errorf("json.Unmarshal discovery: %w", err)
	}

	if cfg.Issuer != p.issuer {
		return ErrIssuerInvalid
	}

	if cfg.JwksURI == "" {
		return errors.New("could not fetch JWKS URI")
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, cfg.JwksURI, nil)
	if err != nil {
		return fmt.Errorf("new jwks request: %w", err)
	}

	response, err = c.Do(req)
	if err != nil {
		return fmt.Errorf("get jwks: %w", err)
	}

	var jwksKeys jsonWebKeySet
	if err = json.NewDecoder(response.Body).Decode(&jwksKeys); err != nil {
		return fmt.Errorf("json.Unmarshal jwks: %w", err)
	}

	if len(jwksKeys.Keys) > 1 {
		return errors.New("multiple public keys is not supported")
	}

	key := jwksKeys.Keys[0]
	if key.Alg != jwt.SigningMethodRS256.Alg() {
		return errors.New("only RS256 algorithm is supported")
	}

	if key.Use != "sig" {
		return errors.New("only sig use is supported")
	}

	if key.Kty != "RSA" {
		return fmt.Errorf("unknown json web key type '%s'", key.Kty)
	}

	if key.N == "" || key.E == "" {
		return fmt.Errorf("invalid RSA key, missing n/e values")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}

	p.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	return nil
}

func (p *Plugin) extractToken(request *http.Request) (string, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return "", ErrHeaderAuthMissing
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, prefixBearer) {
		return "", ErrHeaderAuthMalformed
	}
	parts := strings.Split(auth[len(prefixBearer):], ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%s: should have 3 parts", ErrTokenInvalidFormat)
	}

	return auth[len(prefixBearer):], nil
}

type discoveryConfig struct {
	// Issuer is the identifier of the OP and is used in the tokens as `iss` claim.
	Issuer string `json:"issuer"`

	// JwksURI is the URL of the JSON Web Key Set. This site contains the signing keys that RPs can use to validate the signature.
	// It may also contain the OP's encryption keys that RPs can use to encrypt request to the OP.
	JwksURI string `json:"jwks_uri,omitempty"`
}

// jsonWebKeySet represents a JWK Set object.
type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// jsonWebKey represents a public or private key in JWK format, used for parsing/serializing.
type jsonWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	K   string `json:"k,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
}
