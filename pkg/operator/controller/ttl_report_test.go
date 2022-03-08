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
	ttlExpired, _, err := ttlIsExpired(ttlReportTime, creationTime)
	assert.NoError(t, err)
	assert.False(t, ttlExpired)
}

func TestTTLIsNotExpired(t *testing.T) {
	ttlReportAnnotationStr := "10s"
	ttlReportTime, _ := time.ParseDuration(ttlReportAnnotationStr)
	creationTime := time.Now()
	then := creationTime.Add(time.Duration(-10) * time.Minute)
	ttlExpired, durationToTTLExp, err := ttlIsExpired(ttlReportTime, then)
	t.Logf("Duration to ttl expiration %s, we should rescheduel check", durationToTTLExp)
	assert.NoError(t, err)
	assert.True(t, ttlExpired)
}
