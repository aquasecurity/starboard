package utils

import (
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/gorhill/cronexpr"
	"time"
)

// NextCronDuration check if next cron activation time has exceeded if so return true
// if activation time has not reached return false and remaining time
// in case it failed to parse cron expression return error
func NextCronDuration(cronString string, creationTime time.Time) (time.Duration, error) {
	expr, err := cronexpr.Parse(cronString)
	if err != nil {
		return time.Duration(0), err
	}
	return timeToExpiration(expr.Next(creationTime)), nil
}

//DurationExceeded  check if duration is now meaning zero
func DurationExceeded(duration time.Duration) bool {
	return duration.Nanoseconds() <= 0
}

//timeToExpiration  return the duration between time to expiration
func timeToExpiration(expiresAt time.Time) time.Duration {
	return expiresAt.Sub(ext.NewSystemClock().Now())
}

//NextIntervalExceeded  check if interval for given time has exceeded
func NextIntervalExceeded(interval time.Duration, creationTime time.Time) time.Duration {
	return timeToExpiration(creationTime.Add(interval))
}
