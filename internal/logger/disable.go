package logger

import "sync/atomic"

var discard atomic.Bool

func DiscardLogs() {
	discard.Store(true)
}
