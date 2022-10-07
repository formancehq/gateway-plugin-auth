package gateway_plugin_auth

import (
	"bytes"
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
	RefreshTimeError string
	RefreshTime      string
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next             http.Handler
	issuer           string
	signingMethodRSA *jwt.SigningMethodRSA
	publicKey        *rsa.PublicKey
	refreshTimeError time.Duration
	refreshTime      time.Duration
}

const (
	refreshTimeErrorDefault = 10 * time.Second
	refreshTimeDefault      = 15 * time.Minute
)

var (
	signingMethodDefault = jwt.SigningMethodRS256
)

func New(ctx context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	fmt.Printf("NEW CONFIG: %+v\n", config)

	p := &Plugin{
		next:   next,
		issuer: config.Issuer,
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

	if config.RefreshTimeError == "" {
		p.refreshTimeError = refreshTimeErrorDefault
	} else {
		rtErr, err := time.ParseDuration(config.RefreshTimeError)
		if err != nil {
			return p, fmt.Errorf("parsing refresh time error: %w", err)
		}
		p.refreshTimeError = rtErr
	}

	if config.RefreshTime == "" {
		p.refreshTime = refreshTimeDefault
	} else {
		rt, err := time.ParseDuration(config.RefreshTime)
		if err != nil {
			return p, fmt.Errorf("parsing refresh time: %w", err)
		}
		p.refreshTime = rt
	}

	go p.backgroundRefreshPublicKeys(ctx)
	if err := p.fetchPublicKeys(ctx); err != nil {
		fmt.Printf("fetchPublicKeys: ERROR: %s\n", err)
	}

	return p, nil
}

func (p *Plugin) backgroundRefreshPublicKeys(ctx context.Context) {
	select {
	case <-ctx.Done():
		fmt.Printf("backgroundRefreshPublicKeys: context done\n")
		return
	case <-time.After(p.refreshTime):
	}

	for {
		if err := p.fetchPublicKeys(ctx); err != nil {
			fmt.Printf("backgroundRefreshPublicKeys: ERROR: %s\n", err)
			select {
			case <-ctx.Done():
				fmt.Printf("backgroundRefreshPublicKeys: ERROR: context done\n")
				return
			case <-time.After(p.refreshTimeError):
				continue
			}
		} else {
			fmt.Printf("backgroundRefreshPublicKeys: SUCCESS\n")
			select {
			case <-ctx.Done():
				fmt.Printf("backgroundRefreshPublicKeys: SUCCESS: context done\n")
				return
			case <-time.After(p.refreshTime):
				continue
			}
		}
	}
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("REQUEST: %+v\n", r)
	token, err := p.extractToken(r)
	if err != nil {
		err := fmt.Errorf("bearer token: %w", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := p.validateToken(token); err != nil {
		// Force refresh public keys and try filtering the request again
		if err := p.fetchPublicKeys(r.Context()); err != nil {
			fmt.Printf("force refresh public keys: ERROR: %s\n", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		fmt.Printf("force refresh public keys: SUCCESS\n")

		if err := p.validateToken(token); err == nil {
			p.next.ServeHTTP(w, r)
			return
		}

		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(w, r)
}

func (p *Plugin) validateToken(tokenString string) error {
	claims := &jwt.StandardClaims{}
	parser := new(jwt.Parser)
	token, parts, err := parseUnverified(tokenString, claims, parser)
	if err != nil {
		return fmt.Errorf("parsed bearer token: %w", err)
	}

	if err := claims.Valid(); err != nil {
		return fmt.Errorf("unvalid bearer token claims: %w", err)
	}

	if token.Method.Alg() != p.signingMethodRSA.Alg() {
		return fmt.Errorf("unsupported token signing method: %s", token.Method.Alg())
	}

	vErr := &jwt.ValidationError{}
	token.Signature = parts[2]
	if err = verifyRSA(strings.Join(parts[0:2], "."), token.Signature, p.publicKey, p.signingMethodRSA); err != nil {
		vErr.Inner = err
		vErr.Errors |= jwt.ValidationErrorSignatureInvalid
		return fmt.Errorf("unverified JWT token: %w", vErr)
	}

	return nil
}

func verifyRSA(signingString, signature string, rsaKey *rsa.PublicKey, m *jwt.SigningMethodRSA) error {
	var err error
	var sig []byte
	if sig, err = base64.RawURLEncoding.DecodeString(signature); err != nil {
		return fmt.Errorf("base64.RawURLEncoding.DecodeString: %w", err)
	}

	if !m.Hash.Available() {
		return fmt.Errorf("the requested hash function is unavailable: %s", m.Hash)
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

func (p *Plugin) fetchPublicKeys(ctx context.Context) error {
	c := http.DefaultClient
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer+discoveryEndpoint, nil)
	if err != nil {
		return fmt.Errorf("discovery request: %w", err)
	}

	response, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("get discovery: %w", err)
	}

	var cfg discoveryConfig
	if err = json.NewDecoder(response.Body).Decode(&cfg); err != nil {
		return fmt.Errorf("decoding discovery: %w", err)
	}

	if cfg.Issuer != p.issuer {
		return errors.New("issuer does not match")
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

	oldPub := p.publicKey

	p.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	if oldPub != nil && p.publicKey != nil && !oldPub.Equal(p.publicKey) {
		fmt.Printf("FETCH PUBLIC KEY: public key changed: %+v\n", p.publicKey)
	} else {
		fmt.Printf("FETCH PUBLIC KEY: %+v\n", p.publicKey)
	}

	return nil
}

func (p *Plugin) extractToken(request *http.Request) (string, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return "", errors.New("missing authorization header")
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, prefixBearer) {
		return "", errors.New("malformed authorization header")
	}
	parts := strings.Split(auth[len(prefixBearer):], ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid format: should have 3 parts")
	}

	return auth[len(prefixBearer):], nil
}

func parseUnverified(tokenString string, claims *jwt.StandardClaims, p *jwt.Parser) (token *jwt.Token, parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	token = &jwt.Token{Raw: tokenString}

	var headerBytes []byte
	if headerBytes, err = jwt.DecodeSegment(parts[0]); err != nil {
		return token, parts, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, parts, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	token.Claims = claims

	var claimBytes []byte
	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return token, parts, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}

	if err := dec.Decode(&claims); err != nil {
		return token, parts, &jwt.ValidationError{Inner: err, Errors: jwt.ValidationErrorMalformed}
	}

	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = jwt.GetSigningMethod(method); token.Method == nil {
			return token, parts, jwt.NewValidationError("signing method (alg) is unavailable.", jwt.ValidationErrorUnverifiable)
		}
	} else {
		return token, parts, jwt.NewValidationError("signing method (alg) is unspecified.", jwt.ValidationErrorUnverifiable)
	}

	return token, parts, nil
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
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}
