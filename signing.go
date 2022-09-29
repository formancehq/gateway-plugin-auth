package gateway_plugin_auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"golang.org/x/crypto/ed25519"
)

// NonceSource represents a source of random nonces to go into JWS objects
type NonceSource interface {
	Nonce() (string, error)
}

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer interface {
	Sign(payload []byte) (*JSONWebSignature, error)
	Options() SignerOptions
}

// SigningKey represents an algorithm/key used to sign a message.
type SigningKey struct {
	Algorithm SignatureAlgorithm
	Key       interface{}
}

// SignerOptions represents options that can be set when creating signers.
type SignerOptions struct {
	NonceSource NonceSource
	EmbedJWK    bool

	// Optional map of additional keys to be inserted into the protected header
	// of a JWS object. Some specifications which make use of JWS like to insert
	// additional values here. All values must be JSON-serializable.
	ExtraHeaders map[HeaderKey]interface{}
}

// WithHeader adds an arbitrary value to the ExtraHeaders map, initializing it
// if necessary. It returns itself and so can be used in a fluent style.
func (so *SignerOptions) WithHeader(k HeaderKey, v interface{}) *SignerOptions {
	if so.ExtraHeaders == nil {
		so.ExtraHeaders = map[HeaderKey]interface{}{}
	}
	so.ExtraHeaders[k] = v
	return so
}

// WithContentType adds a content type ("cty") header and returns the updated
// SignerOptions.
func (so *SignerOptions) WithContentType(contentType ContentType) *SignerOptions {
	return so.WithHeader(HeaderContentType, contentType)
}

// WithType adds a type ("typ") header and returns the updated SignerOptions.
func (so *SignerOptions) WithType(typ ContentType) *SignerOptions {
	return so.WithHeader(HeaderType, typ)
}

// WithCritical adds the given names to the critical ("crit") header and returns
// the updated SignerOptions.
func (so *SignerOptions) WithCritical(names ...string) *SignerOptions {
	if so.ExtraHeaders[headerCritical] == nil {
		so.WithHeader(headerCritical, make([]string, 0, len(names)))
	}
	crit := so.ExtraHeaders[headerCritical].([]string)
	so.ExtraHeaders[headerCritical] = append(crit, names...)
	return so
}

// WithBase64 adds a base64url-encode payload ("b64") header and returns the updated
// SignerOptions. When the "b64" value is "false", the payload is not base64 encoded.
func (so *SignerOptions) WithBase64(b64 bool) *SignerOptions {
	if !b64 {
		so.WithHeader(headerB64, b64)
		so.WithCritical(headerB64)
	}
	return so
}

type payloadSigner interface {
	signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error)
}

type payloadVerifier interface {
	verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error
}

type recipientSigInfo struct {
	sigAlg    SignatureAlgorithm
	publicKey func() *JSONWebKey
	signer    payloadSigner
}

func staticPublicKey(jwk *JSONWebKey) func() *JSONWebKey {
	return func() *JSONWebKey {
		return jwk
	}
}

// newVerifier creates a verifier based on the key type
func newVerifier(verificationKey interface{}) (payloadVerifier, error) {
	switch verificationKey := verificationKey.(type) {
	case ed25519.PublicKey:
		return &edEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case *rsa.PublicKey:
		return &rsaEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case *ecdsa.PublicKey:
		return &ecEncrypterVerifier{
			publicKey: verificationKey,
		}, nil
	case []byte:
		return &symmetricMac{
			key: verificationKey,
		}, nil
	case JSONWebKey:
		return newVerifier(verificationKey.Key)
	case *JSONWebKey:
		return newVerifier(verificationKey.Key)
	}
	if ov, ok := verificationKey.(OpaqueVerifier); ok {
		return &opaqueVerifier{verifier: ov}, nil
	}
	return nil, ErrUnsupportedKeyType
}

func makeJWSRecipient(alg SignatureAlgorithm, signingKey interface{}) (recipientSigInfo, error) {
	switch signingKey := signingKey.(type) {
	case ed25519.PrivateKey:
		return newEd25519Signer(alg, signingKey)
	case *rsa.PrivateKey:
		return newRSASigner(alg, signingKey)
	case *ecdsa.PrivateKey:
		return newECDSASigner(alg, signingKey)
	case []byte:
		return newSymmetricSigner(alg, signingKey)
	case JSONWebKey:
		return newJWKSigner(alg, signingKey)
	case *JSONWebKey:
		return newJWKSigner(alg, *signingKey)
	}
	if signer, ok := signingKey.(OpaqueSigner); ok {
		return newOpaqueSigner(alg, signer)
	}
	return recipientSigInfo{}, ErrUnsupportedKeyType
}

func newJWKSigner(alg SignatureAlgorithm, signingKey JSONWebKey) (recipientSigInfo, error) {
	recipient, err := makeJWSRecipient(alg, signingKey.Key)
	if err != nil {
		return recipientSigInfo{}, err
	}
	if recipient.publicKey != nil && recipient.publicKey() != nil {
		// recipient.publicKey is a JWK synthesized for embedding when recipientSigInfo
		// was created for the inner key (such as a RSA or ECDSA public key). It contains
		// the pub key for embedding, but doesn't have extra params like key id.
		publicKey := signingKey
		publicKey.Key = recipient.publicKey().Key
		recipient.publicKey = staticPublicKey(&publicKey)

		// This should be impossible, but let's check anyway.
		if !recipient.publicKey().IsPublic() {
			return recipientSigInfo{}, errors.New("square/go-jose: public key was unexpectedly not public")
		}
	}
	return recipient, nil
}

// Verify validates the signature on the object and returns the payload.
// This function does not support multi-signature, if you desire multi-sig
// verification use VerifyMulti instead.
//
// Be careful when verifying signatures based on embedded JWKs inside the
// payload header. You cannot assume that the key received in a payload is
// trusted.
func (obj JSONWebSignature) Verify(verificationKey interface{}) ([]byte, error) {
	err := obj.DetachedVerify(obj.payload, verificationKey)
	if err != nil {
		return nil, err
	}
	return obj.payload, nil
}

// UnsafePayloadWithoutVerification returns the payload without
// verifying it. The content returned from this function cannot be
// trusted.
func (obj JSONWebSignature) UnsafePayloadWithoutVerification() []byte {
	return obj.payload
}

// DetachedVerify validates a detached signature on the given payload. In
// most cases, you will probably want to use Verify instead. DetachedVerify
// is only useful if you have a payload and signature that are separated from
// each other.
func (obj JSONWebSignature) DetachedVerify(payload []byte, verificationKey interface{}) error {
	verifier, err := newVerifier(verificationKey)
	if err != nil {
		return err
	}

	if len(obj.Signatures) > 1 {
		return errors.New("square/go-jose: too many signatures in payload; expecting only one")
	}

	signature := obj.Signatures[0]
	headers := signature.mergedHeaders()
	critical, err := headers.getCritical()
	if err != nil {
		return err
	}

	for _, name := range critical {
		if !supportedCritical[name] {
			return ErrCryptoFailure
		}
	}

	input, err := obj.computeAuthData(payload, &signature)
	if err != nil {
		return ErrCryptoFailure
	}

	alg := headers.getSignatureAlgorithm()
	err = verifier.verifyPayload(input, signature.Signature, alg)
	if err == nil {
		return nil
	}

	return ErrCryptoFailure
}