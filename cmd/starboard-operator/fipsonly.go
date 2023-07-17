//go:build fipsonly

package tls

import (
	_ "crypto/tls/fipsonly"
)
