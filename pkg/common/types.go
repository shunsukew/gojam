package common

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	HashLength = 32
)

type Hash [HashLength]byte

func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) Hash {
	return BytesToHash(FromHex(s))
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := FromHex(s)
	if len(bytes) != HashLength {
		return errors.New("invalid hash length")
	}

	copy(h[:], bytes)

	return nil
}

func (h *Hash) ToHex() string {
	return "0x" + hex.EncodeToString(h[:])
}

type Blob []byte

func HexToBlob(s string) Blob {
	return FromHex(s)
}

func (b *Blob) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	*b = FromHex(s)

	return nil
}

// ℕ_L
type BlobLength uint32
