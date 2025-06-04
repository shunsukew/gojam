package codec

func Decode(data []byte, v interface{}) error {
	// TODO: implement actual decode logic
	// Placeholder for decoding logic
	return nil
}

// TODO: Sequence length prefix handling
// Currently, only handling known length of bits sequence.
// We might need to add length prefix handling both for encoding and decoding later.
// See bit sequence codec definition in the gray paper Appendix C.1.5. Bit Sequence Encoding.
func DecodeBitSequence(bytes []byte, bitCount int) []bool {
	bits := make([]bool, 0, bitCount)

	for i := 0; i < bitCount; i++ {
		byteIndex := i / 8
		bitPosition := i % 8 // LSB-first

		bit := (bytes[byteIndex] >> bitPosition) & 1
		bits = append(bits, bit == 1)
	}

	return bits
}
