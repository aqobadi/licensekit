package protocol

import "time"

// EpochUnix is 2020-01-01T00:00:00Z, day 0 (spec §9).
const EpochUnix int64 = 1577836800

// Today returns the UTC day number for a Unix time, and false if the time is
// before the epoch (which the SDK treats as a clock problem).
func Today(unix int64) (int64, bool) {
	if unix < EpochUnix {
		return 0, false
	}
	return (unix - EpochUnix) / 86400, true
}

// Date returns the UTC date of a day number.
func Date(day int64) time.Time {
	return time.Unix(EpochUnix+day*86400, 0).UTC()
}

// DayOf returns the day number of a date (its UTC calendar day).
func DayOf(t time.Time) int64 {
	t = t.UTC()
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return (d.Unix() - EpochUnix) / 86400
}

// ExpiryDay returns the last valid day of a term of months starting on the
// start day (spec B §1): the day before the same day-of-month in the target
// month, or the target month's last day if that day does not exist.
func ExpiryDay(startDay int64, months int) int64 {
	s := Date(startDay)
	y, m := s.Year(), s.Month()+time.Month(months)
	last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC)
	if s.Day() > last.Day() {
		return DayOf(last)
	}
	return DayOf(time.Date(y, m, s.Day()-1, 0, 0, 0, 0, time.UTC))
}

// Valid reports whether a license with expiryDay is valid on today.
func Valid(expiryDay uint16, today int64) bool {
	return expiryDay == 0 || today <= int64(expiryDay)
}
