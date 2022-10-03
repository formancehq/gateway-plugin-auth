package gateway_plugin_auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	Issuer string
}

// CreateConfig creates a new Config.
func CreateConfig() *Config {
	return &Config{}
}

// Plugin contains the runtime config.
type Plugin struct {
	next       http.Handler
	issuer     string
	jwksURI    string
	publicKeys map[string]any
}

type Network struct {
	Client `json:"client"`
}

type Client struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

type JWT struct {
	Plaintext []byte
	Signature []byte
	Header    JwtHeader
	Payload   map[string]any
}

var supportedHeaderNames = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}

// Key is a JSON web key returned by the JWKS request.
type Key struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	K   string   `json:"k,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	D   string   `json:"d,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Crv string   `json:"crv,omitempty"`
}

// Keys represents a set of JSON web keys.
type Keys struct {
	// Keys is an array of JSON web keys.
	Keys []Key `json:"keys"`
}

// New creates a new Plugin
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	p := &Plugin{
		next:       next,
		issuer:     config.Issuer,
		publicKeys: map[string]any{},
	}

	for {
		if err := p.FetchPublicKeys(); err != nil {
			fmt.Printf("ERR FIRST FETCH PUBLIC KEYS: %s\n", err)
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}

	go p.BackgroundRefresh()
	return p, nil
}

func (p *Plugin) BackgroundRefresh() {
	time.Sleep(15 * time.Minute)
	for {
		if err := p.FetchPublicKeys(); err != nil {
			fmt.Printf("ERR FETCH PUBLIC KEYS: %s\n", err)
			time.Sleep(10 * time.Second)
		} else {
			time.Sleep(15 * time.Minute)
		}
	}
}

const (
	discoveryEndpoint = "/.well-known/openid-configuration"
)

type DiscoveryConfig struct {
	// Issuer is the identifier of the OP and is used in the tokens as `iss` claim.
	Issuer string `json:"issuer"`

	// JwksURI is the URL of the JSON Web Key Set. This site contains the signing keys that RPs can use to validate the signature.
	// It may also contain the OP's encryption keys that RPs can use to encrypt request to the OP.
	JwksURI string `json:"jwks_uri,omitempty"`
}

func (p *Plugin) FetchPublicKeys() error {
	response, err := http.Get(p.issuer + discoveryEndpoint)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	var cfg DiscoveryConfig
	if err = json.Unmarshal(body, &cfg); err != nil {
		return err
	}

	if cfg.JwksURI == "" {
		return errors.New("could not fetch JWKS URI")
	}

	response, err = http.Get(cfg.JwksURI)
	if err != nil {
		return err
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	var jwksKeys Keys
	if err = json.Unmarshal(body, &jwksKeys); err != nil {
		return err
	}

	for _, key := range jwksKeys.Keys {
		switch key.Kty {
		case "RSA":
			if key.Kid == "" {
				key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, key.E, key.N))
				if err != nil {
					return err
				}
			}
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return err
			}
			ptr := new(rsa.PublicKey)
			ptr.N = new(big.Int).SetBytes(nBytes)
			ptr.E = int(new(big.Int).SetBytes(eBytes).Uint64())
			p.publicKeys[key.Kid] = ptr
		case "EC":
			if key.Kid == "" {
				key.Kid, err = JWKThumbprint(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, key.X, key.Y))
				if err != nil {
					return err
				}
			}
			var crv elliptic.Curve
			switch key.Crv {
			case "P-256":
				crv = elliptic.P256()
			case "P-384":
				crv = elliptic.P384()
			case "P-521":
				crv = elliptic.P521()
			default:
				switch key.Alg {
				case "ES256":
					crv = elliptic.P256()
				case "ES384":
					crv = elliptic.P384()
				case "ES512":
					crv = elliptic.P521()
				default:
					crv = elliptic.P256()
				}
			}
			xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
			if err != nil {
				return err
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
			if err != nil {
				return err
			}
			ptr := new(ecdsa.PublicKey)
			ptr.Curve = crv
			ptr.X = new(big.Int).SetBytes(xBytes)
			ptr.Y = new(big.Int).SetBytes(yBytes)
			p.publicKeys[key.Kid] = ptr
		case "oct":
			kBytes, err := base64.RawURLEncoding.DecodeString(key.K)
			if err != nil {
				return err
			}
			if key.Kid == "" {
				key.Kid, err = JWKThumbprint(key.K)
				if err != nil {
					return err
				}
			}
			p.publicKeys[key.Kid] = kBytes
		}
	}

	return nil
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jwtToken, err := p.ExtractToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if err = p.VerifyToken(jwtToken); err != nil {
		err = fmt.Errorf("%s: %w", ErrTokenVerification, err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(w, r)
}

const (
	bearerToken  = "Bearer"
	prefixBearer = bearerToken + " "
)

var (
	ErrHeaderAuthMissing   = errors.New("missing authorization header")
	ErrHeaderAuthMalformed = errors.New("malformed authorization header")
	ErrTokenInvalidFormat  = "invalid token format"
)

func (p *Plugin) ExtractToken(request *http.Request) (*JWT, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return nil, ErrHeaderAuthMissing
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, prefixBearer) {
		return nil, ErrHeaderAuthMalformed
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%s: should have 3 parts", ErrTokenInvalidFormat)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%s (header): %w", ErrTokenInvalidFormat, err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%s (payload): %w", ErrTokenInvalidFormat, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%s (signature): %w", ErrTokenInvalidFormat, err)
	}
	jwtToken := JWT{
		Plaintext: []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature: signature,
	}
	if err = json.Unmarshal(header, &jwtToken.Header); err != nil {
		return nil, fmt.Errorf("%s (header): %w", ErrTokenInvalidFormat, err)
	}
	d := json.NewDecoder(bytes.NewBuffer(payload))
	d.UseNumber()
	if err = d.Decode(&jwtToken.Payload); err != nil {
		return nil, fmt.Errorf("%s (payload): %w", ErrTokenInvalidFormat, err)
	}

	return &jwtToken, nil
}

var ErrTokenVerification = "token verification failed"

func (p *Plugin) VerifyToken(jwtToken *JWT) error {
	for _, h := range jwtToken.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			return fmt.Errorf("unsupported header: %s", h)
		}
	}

	a, ok := tokenAlgorithms[jwtToken.Header.Alg]
	if !ok {
		return fmt.Errorf("unknown JWS algorithm: %s", jwtToken.Header.Alg)
	}

	for _, key := range p.publicKeys {
		err := a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
		fmt.Printf("VERIFY TOKEN ERR: %s\n", err)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("%d keys", len(p.publicKeys))
}

type tokenVerifyFunction func(key any, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key any, hash crypto.Hash, digest []byte, signature []byte) error

// jwtAlgorithm describes a JWS 'alg' value
type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

// tokenAlgorithms is the known JWT algorithms
var tokenAlgorithms = map[string]tokenAlgorithm{
	"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
	"RS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPKCS)},
	"RS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPKCS)},
	"PS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPSS)},
	"PS384": {crypto.SHA384, verifyAsymmetric(verifyRSAPSS)},
	"PS512": {crypto.SHA512, verifyAsymmetric(verifyRSAPSS)},
	"ES256": {crypto.SHA256, verifyAsymmetric(verifyECDSA)},
	"ES384": {crypto.SHA384, verifyAsymmetric(verifyECDSA)},
	"ES512": {crypto.SHA512, verifyAsymmetric(verifyECDSA)},
	"HS256": {crypto.SHA256, verifyHMAC},
	"HS384": {crypto.SHA384, verifyHMAC},
	"HS512": {crypto.SHA512, verifyHMAC},
}

// errSignatureNotVerified is returned when a signature cannot be verified.
func verifyHMAC(key any, hash crypto.Hash, payload []byte, signature []byte) error {
	macKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("incorrect symmetric key type")
	}
	mac := hmac.New(hash.New, macKey)
	if _, err := mac.Write(payload); err != nil {
		return err
	}
	sum := mac.Sum([]byte{})
	if !hmac.Equal(signature, sum) {
		return fmt.Errorf("(HMAC)")
	}
	return nil
}

func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key any, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key any, hash crypto.Hash, hashed []byte, sig []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, hashed, sig); err != nil {
		return fmt.Errorf("RSAPKCS: %w", err)
	}
	return nil
}

func verifyRSAPSS(key any, hash crypto.Hash, digest []byte, sig []byte) error {
	publicKeyRsa, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	if err := rsa.VerifyPSS(publicKeyRsa, hash, digest, sig, nil); err != nil {
		return fmt.Errorf("RSAPSS: %w", err)
	}
	return nil
}

func verifyECDSA(key any, _ crypto.Hash, digest []byte, sig []byte) error {
	publicKeyEcdsa, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("incorrect public key type")
	}
	r, s := &big.Int{}, &big.Int{}
	n := len(sig) / 2
	r.SetBytes(sig[:n])
	s.SetBytes(sig[n:])
	if ecdsa.Verify(publicKeyEcdsa, digest, r, s) {
		return nil
	}
	return fmt.Errorf("ECDSA")
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(jwk string) (string, error) {
	b := sha256.Sum256([]byte(jwk))
	var slice []byte
	for _, s := range b {
		slice = append(slice, s)
	}
	return base64.RawURLEncoding.EncodeToString(slice), nil
}
