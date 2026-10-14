package wxhook

import "time"

func captureRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return captureRetryBase
	}
	delay := captureRetryBase
	for i := 0; i < failures && delay < captureRetryMax; i++ {
		delay *= 2
	}
	if delay > captureRetryMax {
		return captureRetryMax
	}
	return delay
}
