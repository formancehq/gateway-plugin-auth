package gateway_plugin_auth

import (
	"crypto"
	"encoding/binary"
	"hash"
	"io"
)

type concatKDF struct {
	z, info []byte
	i       uint32
	cache   []byte
	hasher  hash.Hash
}

// NewConcatKDF builds a KDF reader based on the given inputs.
func NewConcatKDF(hash crypto.Hash, z, algID, ptyUInfo, ptyVInfo, supPubInfo, supPrivInfo []byte) io.Reader {
	buffer := make([]byte, uint64(len(algID))+uint64(len(ptyUInfo))+uint64(len(ptyVInfo))+uint64(len(supPubInfo))+uint64(len(supPrivInfo)))
	n := 0
	n += copy(buffer, algID)
	n += copy(buffer[n:], ptyUInfo)
	n += copy(buffer[n:], ptyVInfo)
	n += copy(buffer[n:], supPubInfo)
	copy(buffer[n:], supPrivInfo)

	hasher := hash.New()

	return &concatKDF{
		z:      z,
		info:   buffer,
		hasher: hasher,
		cache:  []byte{},
		i:      1,
	}
}

func (ctx *concatKDF) Read(out []byte) (int, error) {
	copied := copy(out, ctx.cache)
	ctx.cache = ctx.cache[copied:]

	for copied < len(out) {
		ctx.hasher.Reset()

		// Write on a hash.Hash never fails
		_ = binary.Write(ctx.hasher, binary.BigEndian, ctx.i)
		_, _ = ctx.hasher.Write(ctx.z)
		_, _ = ctx.hasher.Write(ctx.info)

		hash := ctx.hasher.Sum(nil)
		chunkCopied := copy(out[copied:], hash)
		copied += chunkCopied
		ctx.cache = hash[chunkCopied:]

		ctx.i++
	}

	return copied, nil
}
