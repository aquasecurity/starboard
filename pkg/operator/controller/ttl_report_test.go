package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTTLIsExpired(t *testing.T) {
	ttlReportAnnotationStr := "10h"
	ttlReportTime, _ := time.ParseDuration(ttlReportAnnotationStr)
	creationTime := time.Now()
	ttlExpired := ttlIsExpired(ttlReportTime, creationTime)
	assert.False(t, durationExceeded(ttlExpired))
}

func TestTTLIsNotExpired(t *testing.T) {
	ttlReportAnnotationStr := "10s"
	ttlReportTime, _ := time.ParseDuration(ttlReportAnnotationStr)
	creationTime := time.Now()
	then := creationTime.Add(time.Duration(-10) * time.Minute)
	ttlExpired := ttlIsExpired(ttlReportTime, then)
	t.Logf("Duration to ttl expiration %s, we should rescheduel check", ttlExpired.String())
	assert.True(t, durationExceeded(ttlExpired))
}
