package scanners

import (
	"time"

	"k8s.io/utils/pointer"
)

func GetActiveDeadlineSeconds(d time.Duration) (timeout *int64) {
	if d > 0 {
		timeout = pointer.Int64Ptr(int64(d.Seconds()))
		return
	}
	return
}
