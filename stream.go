package gateway_plugin_auth

import (
	"encoding/json"
	"errors"
)

// RawMessage is a raw encoded JSON object.
// It implements Marshaler and Unmarshaler and can
// be used to delay JSON decoding or precompute a JSON encoding.
type RawMessage []byte

// MarshalJSON returns *m as the JSON encoding of m.
func (m *RawMessage) MarshalJSON() ([]byte, error) {
	return *m, nil
}

// UnmarshalJSON sets *m to a copy of data.
func (m *RawMessage) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("json.RawMessage: UnmarshalJSON on nil pointer")
	}
	*m = append((*m)[0:0], data...)
	return nil
}

var _ json.Marshaler = (*RawMessage)(nil)
var _ json.Unmarshaler = (*RawMessage)(nil)

// A Token holds a value of one of these types:
//
//	Delim, for the four JSON delimiters [ ] { }
//	bool, for JSON booleans
//	float64, for JSON numbers
//	Number, for JSON numbers
//	string, for JSON string literals
//	nil, for JSON null
type Token interface{}

// A Delim is a JSON array or object delimiter, one of [ ] { or }.
type Delim rune

func (d Delim) String() string {
	return string(d)
}
