package bls

import (
	"encoding/json"
	"errors"

	"github.com/shunsukew/gojam/pkg/common"
)

const (
	BlsKeySize = 144
)

type BLSKey [BlsKeySize]byte

func (pk *BLSKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bytes := common.FromHex(s)
	if len(bytes) != BlsKeySize {
		return errors.New("invalid bls private key length")
	}
	copy(pk[:], bytes)

	return nil
}
