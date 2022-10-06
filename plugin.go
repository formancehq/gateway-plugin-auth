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

	for {
		if err := p.fetchPublicKeys(ctx); err != nil {
			fmt.Printf("ERROR: Plugin.fetchPublicKeys: %s\n", err)
		} else {
			//go p.backgroundRefresh(ctx)
			fmt.Printf("NEW PLUGIN: %+v\n", p)
			return p, nil
		}
		select {
		case <-ctx.Done():
			fmt.Printf("NEW PLUGIN: context done\n")
			return p, nil
		case <-time.After(p.refreshTimeError):
			continue
		}
	}
}

func (p *Plugin) backgroundRefresh(ctx context.Context) {
	fmt.Printf("REFRESH WITH PLUGIN: %+v\n", p)
	select {
	case <-ctx.Done():
		fmt.Printf("REFRESH: context done\n")
		return
	case <-time.After(p.refreshTime):
	}
	for {
		if err := p.fetchPublicKeys(ctx); err != nil {
			fmt.Printf("REFRESH ERROR: Plugin.fetchPublicKeys: %s\n", err)
			select {
			case <-ctx.Done():
				fmt.Printf("REFRESH: context done error\n")
				return
			case <-time.After(p.refreshTimeError):
				continue
			}
		} else {
			select {
			case <-ctx.Done():
				fmt.Printf("REFRESH: context done success\n")
				return
			case <-time.After(p.refreshTime):
				continue
			}
		}
	}
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("REQUEST: %+v\n", r)
	tokenString, err := p.extractToken(r)
	if err != nil {
		http.Error(w, fmt.Errorf("extracting bearer token: %w", err).Error(), http.StatusUnauthorized)
		return
	}

	parser := new(jwt.Parser)
	token, parts, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		http.Error(w, fmt.Errorf("parsing bearer token: %w", err).Error(), http.StatusUnauthorized)
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
		fmt.Printf("UNVERIFIED TOKEN: %+v\n", token)
		return
	}

	fmt.Printf("VERIFIED TOKEN: %+v\n", token)
	p.next.ServeHTTP(w, r)
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

	oldPub := &rsa.PublicKey{}
	if p.publicKey != nil {
		oldPub = p.publicKey
	}

	p.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	if p.publicKey != nil && oldPub.Equal(p.publicKey) {
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
		return "", fmt.Errorf("invalid token format: should have 3 parts")
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
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}
