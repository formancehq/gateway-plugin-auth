package gateway_plugin_auth

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"unicode"
)

// Helper function to serialize known-good objects.
// Precondition: value is not a nil pointer.
func mustSerializeJSON(value interface{}) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	// We never want to serialize the top-level value "null," since it's not a
	// valid JOSE message. But if a caller passes in a nil pointer to this method,
	// MarshalJSON will happily serialize it as the top-level value "null". If
	// that value is then embedded in another operation, for instance by being
	// base64-encoded and fed as input to a signing algorithm
	// (https://github.com/square/go-jose/issues/22), the result will be
	// incorrect. Because this method is intended for known-good objects, and a nil
	// pointer is not a known-good object, we are free to panic in this case.
	// Note: It's not possible to directly check whether the data pointed at by an
	// interface is a nil pointer, so we do this hacky workaround.
	// https://groups.google.com/forum/#!topic/golang-nuts/wnH302gBa4I
	if string(out) == "null" {
		panic("Tried to serialize a nil pointer.")
	}
	return out
}

// Strip all newlines and whitespace
func stripWhitespace(data string) string {
	buf := strings.Builder{}
	buf.Grow(len(data))
	for _, r := range data {
		if !unicode.IsSpace(r) {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// Perform decompression based on algorithm
func decompress(algorithm CompressionAlgorithm, input []byte) ([]byte, error) {
	switch algorithm {
	case DEFLATE:
		return inflate(input)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// Decompress with DEFLATE
func inflate(input []byte) ([]byte, error) {
	output := new(bytes.Buffer)
	reader := flate.NewReader(bytes.NewBuffer(input))

	_, err := io.Copy(output, reader)
	if err != nil {
		return nil, err
	}

	err = reader.Close()
	return output.Bytes(), err
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	if len(data) > length {
		panic("square/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return newBuffer(append(pad, data...))
}

func newBufferFromInt(num uint64) *byteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return newBuffer(bytes.TrimLeft(data, "\x00"))
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b *byteBuffer) bytes() []byte {
	// Handling nil here allows us to transparently handle nil slices when serializing.
	if b == nil {
		return nil
	}
	return b.data
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func (b byteBuffer) toInt() int {
	return int(b.bigInt().Int64())
}
