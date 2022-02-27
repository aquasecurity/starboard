package utils

import (
	"github.com/aquasecurity/starboard/pkg/ext"
	"testing"
	"time"
)

func TestNextCronDuration(t *testing.T) {
	tests := []struct {
		name         string
		cron         string
		creationTime string
		wantDuration int
		wantError    string
	}{
		{name: "good cron", cron: "* * * * *", creationTime: "2050-11-12T11:00:00", wantDuration: 251749},
		{name: "bad cron", cron: "* *", creationTime: "2050-11-12T11:00:00", wantError: "missing field(s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := parseTime(tt.creationTime)
			if err != nil {
				t.Errorf(err.Error())
			}
			duration, err := NextCronDuration(tt.cron, tm)
			if err != nil && err.Error() != tt.wantError {
				t.Errorf("TestNextCronDuration want %v got %v", tt.wantError, err.Error())
			}
			if err == nil {
				if int(duration.Hours()) > tt.wantDuration {
					t.Errorf("TestNextCronDuration want %v got %v", tt.wantDuration, int(duration.Hours()))
				}
			}
		})
	}
}
func parseTime(creationTime string) (time.Time, error) {
	layout := "2006-01-02T15:04:05"
	tm, err := time.Parse(layout, creationTime)
	if err != nil {
		return ext.NewSystemClock().Now(), err
	}
	return tm, nil
}
func TestDurationExceeded(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     bool
	}{
		{name: "duration future", duration: time.Duration(100), want: false},
		{name: "duration now", duration: time.Duration(0), want: true},
		{name: "duration pass", duration: time.Duration(-2), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceded := DurationExceeded(tt.duration)
			if exceded != tt.want {
				t.Errorf("TestDurationExceeded want %v got %v", tt.want, exceded)
			}
		})
	}
}

func TestNextIntervalExceeded(t *testing.T) {
	tests := []struct {
		name         string
		creationTime string
		duration     time.Duration
		want         bool
	}{
		{name: "duration future", duration: time.Duration(100), creationTime: "2050-11-12T11:00:00", want: true},
		{name: "duration pass", duration: time.Duration(-2), creationTime: "2014-11-12T11:00:00", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := parseTime(tt.creationTime)
			if err != nil {
				t.Errorf(err.Error())
			}
			exceeded := NextIntervalExceeded(tt.duration, tm)
			if DurationExceeded(exceeded) && tt.want {
				t.Errorf("TestNextIntervalExceeded want %v got %v", tt.want, exceeded)
			}
		})
	}
}
