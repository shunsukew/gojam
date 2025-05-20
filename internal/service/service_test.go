package service

import (
	"testing"

	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/stretchr/testify/assert"
)

func TestPreimageAvailability(t *testing.T) {
	tests := []struct {
		name                string
		availabilityHistory PreimageAvailabilityHistory
		timeSlot            jamtime.TimeSlot
		expected            bool
	}{
		{
			name:                "Empty history",
			availabilityHistory: PreimageAvailabilityHistory{},
			timeSlot:            10,
			expected:            false,
		},
		{
			name:                "Preimage is unavailable with single timeslot history - timeSlot < history[0]",
			availabilityHistory: PreimageAvailabilityHistory{10},
			timeSlot:            9,
			expected:            false,
		},
		{
			name:                "Preimage is available with single timeslot history - history[0] = timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10},
			timeSlot:            10,
			expected:            true,
		},
		{
			name:                "Preimage is available with single timeslot history - history[0] < timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10},
			timeSlot:            11,
			expected:            true,
		},
		{
			name:                "Preimage is unavailable with two timeslot history - timeSlot < history[0]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20},
			timeSlot:            9,
			expected:            false,
		},
		{
			name:                "Preimage is available with two timeslot history - history[0] = timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10, 20},
			timeSlot:            10,
			expected:            true,
		},
		{
			name:                "Preimage is available with two timeslot history - history[0] < timeSlot < history[1]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20},
			timeSlot:            15,
			expected:            true,
		},
		{
			name:                "Preimage is unavailable with two timeslot history - timeSlot = history[1]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20},
			timeSlot:            20,
			expected:            false,
		},
		{
			name:                "Preimage is unavailable with two timeslot history - history[1] < timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10, 20},
			timeSlot:            21,
			expected:            false,
		},
		{
			name:                "Preimage is unavailable with three timeslot history - timeSlot < history[0]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            9,
			expected:            false,
		},
		{
			name:                "Preimage is available with three timeslot history - history[0] = timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            10,
			expected:            true,
		},
		{
			name:                "Preimage is available with three timeslot history - history[0] < timeSlot < history[1]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            15,
			expected:            true,
		},
		{
			name:                "Preimage is unavailable with three timeslot history - timeSlot = history[1]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            20,
			expected:            false,
		},
		{
			name:                "Preimage is unavailable with three timeslot history - history[1] < timeSlot < history[2]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            25,
			expected:            false,
		},
		{
			name:                "Preimage is available with three timeslot history - timeSlot = history[2]",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            30,
			expected:            true,
		},
		{
			name:                "Preimage is available with three timeslot history - history[2] < timeSlot",
			availabilityHistory: PreimageAvailabilityHistory{10, 20, 30},
			timeSlot:            31,
			expected:            true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isAvailable := test.availabilityHistory.isPreimageAvailableAt(test.timeSlot)
			assert.Equal(t, test.expected, isAvailable, "expected availability to match")
		})
	}
}
