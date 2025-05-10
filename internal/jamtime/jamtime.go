package jamtime

import "time"

// JAM Common Era, the start of JAM protocol, 1200 UTC on January 1, 2025.
var JAMCommonEra = time.Date(2025, time.January, 1, 12, 0, 0, 0, time.UTC)

const (
	TimeSlotDuration = 6 * time.Second                      // P
	EpochDuration    = TimeSlotsPerEpoch * TimeSlotDuration // E * P (= 3600)
)

type JAMTime struct {
	seconds uint64
}

func (jt JAMTime) Before(t2 JAMTime) bool {
	return jt.seconds < t2.seconds
}

func (jt JAMTime) After(t2 JAMTime) bool {
	return jt.seconds > t2.seconds
}

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

type Epoch uint32

func (e1 Epoch) Equal(e2 Epoch) bool {
	return e1 == e2
}

func (e1 Epoch) Before(e2 Epoch) bool {
	return e1 < e2
}

func (e1 Epoch) After(e2 Epoch) bool {
	return e1 > e2
}

func (e1 Epoch) IsNextEpochAfter(e2 Epoch) bool {
	return e1 == e2+1
}

type TimeSlot uint32

func (ts1 TimeSlot) Before(ts2 TimeSlot) bool {
	return ts1 < ts2
}

func (ts1 TimeSlot) After(ts2 TimeSlot) bool {
	return ts1 > ts2
}

func (ts1 TimeSlot) IsNextTimeSlot(ts2 TimeSlot) bool {
	return ts1+1 == ts2
}

func (ts TimeSlot) InTicketSubmissionPeriod() bool {
	return ts.ToTimeSlotInEpoch() < TicketSubmissionDeadline
}

func (ts TimeSlot) ToEpoch() Epoch {
	return Epoch(ts / TimeSlotsPerEpoch)
}

func (ts TimeSlot) ToTimeSlotInEpoch() TimeSlotInEpoch {
	return TimeSlotInEpoch(ts % TimeSlotsPerEpoch)
}

type TimeSlotInEpoch uint32

func (tsie TimeSlotInEpoch) Before(tsie2 TimeSlotInEpoch) bool {
	return tsie < tsie2
}

func (tsie TimeSlotInEpoch) After(tsie2 TimeSlotInEpoch) bool {
	return tsie > tsie2
}

func (tsie TimeSlotInEpoch) IsNextTimeSlot(tsie2 TimeSlotInEpoch) bool {
	return tsie+1 == tsie2
}

func (tsie TimeSlotInEpoch) InTicketSubmissionPeriod() bool {
	return tsie < TicketSubmissionDeadline
}
