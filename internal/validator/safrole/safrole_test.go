package safrole

import (
	"reflect"
	"testing"
)

func TestOutsideInSequence(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		expected []int
	}{
		{
			name:     "Odd length input",
			input:    []int{0, 1, 2, 3, 4, 5, 6},
			expected: []int{0, 6, 1, 5, 2, 4, 3},
		},
		{
			name:     "Even length input",
			input:    []int{0, 1, 2, 3, 4, 5},
			expected: []int{0, 5, 1, 4, 2, 3},
		},
		{
			name:     "Single input",
			input:    []int{42},
			expected: []int{42},
		},
		{
			name:     "Empty input",
			input:    []int{},
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := OutsideInSequence(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}
