package utils

import (
	"time"

	"github.com/xhit/go-str2duration/v2"
)

func TokenTTLValidation(TokenGen time.Time, TokenTTL string) bool {
	duration, err := str2duration.ParseDuration(TokenTTL)

	if err == nil {
		if time.Now().Sub(TokenGen) >= duration {
			return true
		} else {
			return false
		}
	} else {
		return false
	}

}
