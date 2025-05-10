package safrole

import (
	"reflect"
	"testing"

	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
)

func TestSortedAndNonDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		input    []*Ticket
		expected bool
	}{
		{
			name:     "Sorted and non-duplicate tickets",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{2}}, {0, bandersnatch.VrfOutput{3}}, {1, bandersnatch.VrfOutput{4}}},
			expected: true,
		},
		{
			name:     "Not sorted tickets",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{2}}, {1, bandersnatch.VrfOutput{1}}, {0, bandersnatch.VrfOutput{3}}, {1, bandersnatch.VrfOutput{4}}},
			expected: false,
		},
		{
			name:     "Duplicate tickets",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{2}}, {1, bandersnatch.VrfOutput{1}}, {0, bandersnatch.VrfOutput{4}}},
			expected: false,
		},
		{
			name:     "Empty input",
			input:    []*Ticket{},
			expected: true,
		},
		{
			name:     "Single ticket",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{1}}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Tickets(tt.input).IsSortedNonDuplicates()
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSortTickets(t *testing.T) {
	tests := []struct {
		name     string
		input    []*Ticket
		expected []*Ticket
	}{
		{
			name:     "Unsorted tickets",
			input:    []*Ticket{{1, bandersnatch.VrfOutput{2}}, {0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{4}}, {0, bandersnatch.VrfOutput{3}}},
			expected: []*Ticket{{0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{2}}, {0, bandersnatch.VrfOutput{3}}, {1, bandersnatch.VrfOutput{4}}},
		},
		{
			name:     "Already sorted tickets",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{2}}, {0, bandersnatch.VrfOutput{3}}, {1, bandersnatch.VrfOutput{4}}},
			expected: []*Ticket{{0, bandersnatch.VrfOutput{1}}, {1, bandersnatch.VrfOutput{2}}, {0, bandersnatch.VrfOutput{3}}, {1, bandersnatch.VrfOutput{4}}},
		},
		{
			name:     "Empty input",
			input:    []*Ticket{},
			expected: []*Ticket{},
		},
		{
			name:     "Single ticket",
			input:    []*Ticket{{0, bandersnatch.VrfOutput{1}}},
			expected: []*Ticket{{0, bandersnatch.VrfOutput{1}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tickets := Tickets(tt.input)
			tickets.Sort()
			if !reflect.DeepEqual(tickets, Tickets(tt.expected)) {
				t.Errorf("got %v, want %v", tickets, tt.expected)
			}
		})
	}
}

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
