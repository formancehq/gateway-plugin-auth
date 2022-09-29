package gateway_plugin_auth

import (
	"bytes"
	"fmt"
)

func ConcatenateJSON(first, second []byte) ([]byte, error) {
	if !bytes.HasSuffix(first, []byte{'}'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", first)
	}
	if !bytes.HasPrefix(second, []byte{'{'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", second)
	}
	// check empty
	if len(first) == 2 {
		return second, nil
	}
	if len(second) == 2 {
		return first, nil
	}

	first[len(first)-1] = ','
	first = append(first, second[1:]...)
	return first, nil
}
