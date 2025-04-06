package jamtime

import "time"

// JAM Common Era, the start of JAM protocol, 1200 UTC on January 1, 2025.
var JAMCommonEra = time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)

const (
	TimeSlotsPerEpoch = 600                                  // E
	TimeSlotDuration  = 6 * time.Second                      // P
	EpochDuration     = TimeSlotsPerEpoch * TimeSlotDuration // E * P (= 3600)

	TicketSubmissionDeadline = 500 // Y
)

type JAMTime struct {
	seconds uint64
}

type Epoch uint32

type TimeSlot uint32

type TimeSlotInEpoch uint32

func Now() JAMTime {
	now := time.Now().Unix()
	return JAMTime{seconds: uint64(now - JAMCommonEra.Unix())}
}

func FromTime(t time.Time) (JAMTime, error) {
	if t.Before(JAMCommonEra) {
		return JAMTime{}, ErrTimeBeforeJAMCommonEra
	}

	return JAMTime{seconds: uint64(t.Unix() - JAMCommonEra.Unix())}, nil
}

func (jt *JAMTime) Seconds() uint64 {
	return jt.seconds
}

func (jt *JAMTime) TimeSlot() TimeSlot {
	return TimeSlot(jt.seconds / uint64(TimeSlotDuration.Seconds()))
}

func (jt *JAMTime) Epoch() Epoch {
	return Epoch(jt.TimeSlot() / TimeSlotsPerEpoch)
}

func (jt *JAMTime) TimeSlotInEpoch() TimeSlotInEpoch {
	return TimeSlotInEpoch(jt.TimeSlot() % TimeSlotsPerEpoch)
}

func (jt *JAMTime) Time() time.Time {
	return JAMCommonEra.Add(time.Duration(jt.seconds) * time.Second)
}
