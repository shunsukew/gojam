package common

import (
	"bytes"
	"testing"
)

func TestCopyBytes(t *testing.T) {
	input := []byte{1, 2, 3, 4}

	copied := CopyBytes(input)
	if !bytes.Equal(copied, []byte{1, 2, 3, 4}) {
		t.Fatal("not equal after copy")
	}
	copied[0] = 99
	if bytes.Equal(copied, input) {
		t.Fatal("result is not a copy")
	}
}

func TestFromHex(t *testing.T) {
	input := "0x01"
	expected := []byte{1}
	result := FromHex(input)
	if !bytes.Equal(expected, result) {
		t.Errorf("Expected %x got %x", expected, result)
	}
}
