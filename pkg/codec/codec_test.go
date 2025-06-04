package codec

import (
	"testing"

	"github.com/shunsukew/gojam/pkg/common"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeBits(t *testing.T) {
	tests := []struct {
		name     string
		bits     []bool
		expected []byte
	}{
		{
			name:     "empty bits",
			bits:     []bool{},
			expected: []byte{},
		},
		{
			name:     "single true bit",
			bits:     []bool{true},
			expected: []byte{0b00000001},
		},
		{
			name:     "4 bits",
			bits:     []bool{true, false, true, false},
			expected: []byte{0b00000101},
		},
		{
			name:     "8 bits full byte",
			bits:     []bool{true, true, false, false, false, false, false, false},
			expected: []byte{0b00000011},
		},
		{
			name:     "9 bits across bytes",
			bits:     []bool{true, false, false, false, false, false, false, false, true},
			expected: []byte{0b00000001, 0b00000001},
		},
		{
			name:     "from hex string",
			bits:     []bool{true, true, false, false, false, false, false, false},
			expected: common.FromHex("0x03"),
		},
		{
			name: "from hex string large",
			bits: []bool{
				true, false, false, false, false, false, false, false, // 0x01
				false, true, false, false, false, false, false, false, // 0x02
				true, true, false, false, false, false, false, false, // 0x03
			},
			expected: common.FromHex("0x010203"),
		},
	}

	for _, test := range tests {
		t.Run("Encode_"+test.name, func(t *testing.T) {
			actual := EncodeBitSequence(test.bits)
			require.Equal(t, test.expected, actual)
		})

		t.Run("Decode_"+test.name, func(t *testing.T) {
			actual := DecodeBitSequence(test.expected, len(test.bits))
			require.Equal(t, test.bits, actual)
		})
	}
}
