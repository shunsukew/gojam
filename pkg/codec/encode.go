package codec

func Encode(data interface{}) ([]byte, error) {
	// TODO: implement actual encode logic
	return nil, nil
}

func EncodeBitSequence(bits []bool) []byte {
	if len(bits) == 0 {
		return []byte{}
	}

	numBytes := (len(bits) + 7) / 8
	encoded := make([]byte, numBytes)

	for i, bit := range bits {
		if bit {
			byteIndex := i / 8
			bitPosition := i % 8 // LSB-first
			encoded[byteIndex] |= 1 << bitPosition
		}
	}

	return encoded
}
