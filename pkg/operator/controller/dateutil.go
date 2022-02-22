package controller

import (
	"github.com/gorhill/cronexpr"
	"time"
)

// activationTimeExceeded check if next cron activation time has exceeded if so return true
// if activation time has not reached return false and remaining time
// in case it failed to parse cron expression return error
func activationTimeExceeded(cronString string, creationTime time.Time) (time.Duration, error) {
	expr, err := cronexpr.Parse(cronString)
	if err != nil {
		return time.Duration(0), err
	}
	return timeToExpiration(expr.Next(creationTime)), nil
}

//durationExceeded  check if duration is now meaning zero
func durationExceeded(duration time.Duration) bool {
	return duration.Nanoseconds() <= 0
}

//timeToExpiration  return the duration between time to expiration
func timeToExpiration(expiresAt time.Time) time.Duration {
	return expiresAt.Sub(time.Now())
}

//nextIntervalExceeded  check if interval for given time has exceeded
func nextIntervalExceeded(interval time.Duration, creationTime time.Time) time.Duration {
	return timeToExpiration(creationTime.Add(interval))
}
