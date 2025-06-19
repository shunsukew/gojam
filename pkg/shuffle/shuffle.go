package shuffle

import (
	"encoding/binary"

	"github.com/shunsukew/gojam/pkg/common"
	"golang.org/x/crypto/blake2b"
)

// The Fisher-Yates shuffle function.
// Gray Paper Appendix F. Shuffling

func Shuffle[T any](slice []T, hash common.Hash) {
	length := len(slice)
	if length <= 1 {
		return
	}

	seeds := deriveShuffleSeedFromHash(hash, len(slice))

	pool := make([]T, length)
	copy(pool, slice)

	for i := range length {
		l := len(pool)
		index := int(seeds[i] % uint32(l))
		slice[i] = pool[index]
		pool[index] = pool[l-1]
		pool = pool[:l-1]
	}
}

func deriveShuffleSeedFromHash(hash common.Hash, length int) []uint32 {
	output := make([]uint32, length)
	for i := range length {
		// Compute E₄(⌊i/8⌋): 4-byte encoding of integer floor(i/8)
		indexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBytes, uint32(i/8))

		// Compute ℋ(h ⌢ E₄(⌊i/8⌋)) using blake2b
		combined := append(hash[:], indexBytes...)
		digest := blake2b.Sum256(combined)

		offset := (4 * i) % 32
		var chunk []byte
		if offset+4 <= 32 {
			chunk = digest[offset : offset+4]
		} else {
			chunk = append(digest[offset:], digest[:(offset+4)%32]...)
		}

		output[i] = binary.LittleEndian.Uint32(chunk)
	}

	return output
}
