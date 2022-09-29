package gateway_plugin_auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
)

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter interface {
	Encrypt(plaintext []byte) (*JSONWebEncryption, error)
	EncryptWithAuthData(plaintext []byte, aad []byte) (*JSONWebEncryption, error)
	Options() EncrypterOptions
}

// A generic content cipher
type contentCipher interface {
	keySize() int
	encrypt(cek []byte, aad, plaintext []byte) (*aeadParts, error)
	decrypt(cek []byte, aad []byte, parts *aeadParts) ([]byte, error)
}

// A key generator (for generating/getting a CEK)
type keyGenerator interface {
	keySize() int
	genKey() ([]byte, rawHeader, error)
}

// A generic key decrypter
type keyDecrypter interface {
	decryptKey(headers rawHeader, recipient *recipientInfo, generator keyGenerator) ([]byte, error) // Decrypt a key
}

// EncrypterOptions represents options that can be set on new encrypters.
type EncrypterOptions struct {
	Compression CompressionAlgorithm

	// Optional map of additional keys to be inserted into the protected header
	// of a JWS object. Some specifications which make use of JWS like to insert
	// additional values here. All values must be JSON-serializable.
	ExtraHeaders map[HeaderKey]interface{}
}

// WithHeader adds an arbitrary value to the ExtraHeaders map, initializing it
// if necessary. It returns itself and so can be used in a fluent style.
func (eo *EncrypterOptions) WithHeader(k HeaderKey, v interface{}) *EncrypterOptions {
	if eo.ExtraHeaders == nil {
		eo.ExtraHeaders = map[HeaderKey]interface{}{}
	}
	eo.ExtraHeaders[k] = v
	return eo
}

// WithContentType adds a content type ("cty") header and returns the updated
// EncrypterOptions.
func (eo *EncrypterOptions) WithContentType(contentType ContentType) *EncrypterOptions {
	return eo.WithHeader(HeaderContentType, contentType)
}

// WithType adds a type ("typ") header and returns the updated EncrypterOptions.
func (eo *EncrypterOptions) WithType(typ ContentType) *EncrypterOptions {
	return eo.WithHeader(HeaderType, typ)
}

// Recipient represents an algorithm/key to encrypt messages to.
//
// PBES2Count and PBES2Salt correspond with the  "p2c" and "p2s" headers used
// on the password-based encryption algorithms PBES2-HS256+A128KW,
// PBES2-HS384+A192KW, and PBES2-HS512+A256KW. If they are not provided a safe
// default of 100000 will be used for the count and a 128-bit random salt will
// be generated.
type Recipient struct {
	Algorithm  KeyAlgorithm
	Key        interface{}
	KeyID      string
	PBES2Count int
	PBES2Salt  []byte
}

// newDecrypter creates an appropriate decrypter based on the key type
func newDecrypter(decryptionKey interface{}) (keyDecrypter, error) {
	switch decryptionKey := decryptionKey.(type) {
	case *rsa.PrivateKey:
		return &rsaDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case *ecdsa.PrivateKey:
		return &ecDecrypterSigner{
			privateKey: decryptionKey,
		}, nil
	case []byte:
		return &symmetricKeyCipher{
			key: decryptionKey,
		}, nil
	case string:
		return &symmetricKeyCipher{
			key: []byte(decryptionKey),
		}, nil
	case JSONWebKey:
		return newDecrypter(decryptionKey.Key)
	case *JSONWebKey:
		return newDecrypter(decryptionKey.Key)
	}
	if okd, ok := decryptionKey.(OpaqueKeyDecrypter); ok {
		return &opaqueKeyDecrypter{decrypter: okd}, nil
	}
	return nil, ErrUnsupportedKeyType
}

// Decrypt and validate the object and return the plaintext. Note that this
// function does not support multi-recipient, if you desire multi-recipient
// decryption use DecryptMulti instead.
func (obj JSONWebEncryption) Decrypt(decryptionKey interface{}) ([]byte, error) {
	headers := obj.mergedHeaders(nil)

	if len(obj.recipients) > 1 {
		return nil, errors.New("square/go-jose: too many recipients in payload; expecting only one")
	}

	critical, err := headers.getCritical()
	if err != nil {
		return nil, fmt.Errorf("square/go-jose: invalid crit header")
	}

	if len(critical) > 0 {
		return nil, fmt.Errorf("square/go-jose: unsupported crit header")
	}

	decrypter, err := newDecrypter(decryptionKey)
	if err != nil {
		return nil, err
	}

	cipher := getContentCipher(headers.getEncryption())
	if cipher == nil {
		return nil, fmt.Errorf("square/go-jose: unsupported enc value '%s'", string(headers.getEncryption()))
	}

	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}

	authData := obj.computeAuthData()

	var plaintext []byte
	recipient := obj.recipients[0]
	recipientHeaders := obj.mergedHeaders(&recipient)

	cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
	if err == nil {
		// Found a valid CEK -- let's try to decrypt.
		plaintext, err = cipher.decrypt(cek, authData, parts)
	}

	if plaintext == nil {
		return nil, ErrCryptoFailure
	}

	// The "zip" header parameter may only be present in the protected header.
	if comp := obj.protected.getCompression(); comp != "" {
		plaintext, err = decompress(comp, plaintext)
	}

	return plaintext, err
}

// DecryptMulti decrypts and validates the object and returns the plaintexts,
// with support for multiple recipients. It returns the index of the recipient
// for which the decryption was successful, the merged headers for that recipient,
// and the plaintext.
func (obj JSONWebEncryption) DecryptMulti(decryptionKey interface{}) (int, Header, []byte, error) {
	globalHeaders := obj.mergedHeaders(nil)

	critical, err := globalHeaders.getCritical()
	if err != nil {
		return -1, Header{}, nil, fmt.Errorf("square/go-jose: invalid crit header")
	}

	if len(critical) > 0 {
		return -1, Header{}, nil, fmt.Errorf("square/go-jose: unsupported crit header")
	}

	decrypter, err := newDecrypter(decryptionKey)
	if err != nil {
		return -1, Header{}, nil, err
	}

	encryption := globalHeaders.getEncryption()
	cipher := getContentCipher(encryption)
	if cipher == nil {
		return -1, Header{}, nil, fmt.Errorf("square/go-jose: unsupported enc value '%s'", string(encryption))
	}

	generator := randomKeyGenerator{
		size: cipher.keySize(),
	}

	parts := &aeadParts{
		iv:         obj.iv,
		ciphertext: obj.ciphertext,
		tag:        obj.tag,
	}

	authData := obj.computeAuthData()

	index := -1
	var plaintext []byte
	var headers rawHeader

	for i, recipient := range obj.recipients {
		recipientHeaders := obj.mergedHeaders(&recipient)

		cek, err := decrypter.decryptKey(recipientHeaders, &recipient, generator)
		if err == nil {
			// Found a valid CEK -- let's try to decrypt.
			plaintext, err = cipher.decrypt(cek, authData, parts)
			if err == nil {
				index = i
				headers = recipientHeaders
				break
			}
		}
	}

	if plaintext == nil || err != nil {
		return -1, Header{}, nil, ErrCryptoFailure
	}

	// The "zip" header parameter may only be present in the protected header.
	if comp := obj.protected.getCompression(); comp != "" {
		plaintext, err = decompress(comp, plaintext)
	}

	sanitized, err := headers.sanitized()
	if err != nil {
		return -1, Header{}, nil, fmt.Errorf("square/go-jose: failed to sanitize header: %v", err)
	}

	return index, sanitized, plaintext, err
}
