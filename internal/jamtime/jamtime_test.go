package jamtime

import (
	"testing"
	"time"
)

func TestEpochDuration(t *testing.T) {
	if EpochDuration != 3600*time.Second {
		t.Errorf("Expected EpochDuration to be 3600, got %d", EpochDuration)
	}
}

func TestJAMTimeToEpoc(t *testing.T) {
	jt := JAMTime{seconds: 3600}
	if jt.Epoch() != 1 {
		t.Errorf("Expected Epoch to be 1, got %d", jt.Epoch())
	}

	jt = JAMTime{seconds: 3601}
	if jt.Epoch() != 1 {
		t.Errorf("Expected Epoch to be 1, got %d", jt.Epoch())
	}

	jt = JAMTime{seconds: 3599}
	if jt.Epoch() != 0 {
		t.Errorf("Expected Epoch to be 0, got %d", jt.Epoch())
	}
}

func TestJAMTimeToTimeSlot(t *testing.T) {
	jt := JAMTime{seconds: 6}
	if jt.TimeSlot() != 1 {
		t.Errorf("Expected TimeSlot to be 1, got %d", jt.TimeSlot())
	}

	jt = JAMTime{seconds: 7}
	if jt.TimeSlot() != 1 {
		t.Errorf("Expected TimeSlot to be 1, got %d", jt.TimeSlot())
	}

	jt = JAMTime{seconds: 5}
	if jt.TimeSlot() != 0 {
		t.Errorf("Expected TimeSlot to be 0, got %d", jt.TimeSlot())
	}
}

func TestFromTimeToJAMTime(t *testing.T) {
	jamCommonEra := time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)

	t1 := jamCommonEra
	jt, err := FromTime(t1)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if jt.seconds != 0 {
		t.Errorf("Expected seconds to be 0, got %d", jt.seconds)
	}

	t2 := time.Date(2025, time.March, 1, 12, 0, 0, 0, time.UTC)
	jt, err = FromTime(t2)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	diff := t2.Unix() - jamCommonEra.Unix()
	if jt.seconds != uint64(diff) {
		t.Errorf("Expected seconds to be %d, got %d", diff, jt.seconds)
	}

	t3 := time.Date(2025, time.January, 1, 11, 59, 59, 0, time.UTC)
	jt, err = FromTime(t3)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestJAMTimeToTime(t *testing.T) {
	jamCommonEra := time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)

	jt := JAMTime{seconds: 0}
	if jt.Time() != jamCommonEra {
		t.Errorf("Expected time to be %v, got %v", jamCommonEra, jt.Time())
	}

	jt = JAMTime{seconds: 3600}
	if jt.Time() != jamCommonEra.Add(1*time.Hour) {
		t.Errorf("Expected time to be %v, got %v", jamCommonEra.Add(1*time.Hour), jt.Time())
	}
}
