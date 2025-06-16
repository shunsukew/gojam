package safemath

func SaturatingAdd[T ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uint](a, b T) T {
	sum := a + b
	if sum < a {
		return ^T(0) // all bits set, that is max value for T
	}
	return sum
}

func SaturatingSub[T ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uint](a, b T) T {
	if a < b {
		return 0
	}
	return a - b
}
