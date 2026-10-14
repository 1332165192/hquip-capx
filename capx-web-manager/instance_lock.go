package main

import "errors"

var errLifecycleLockBusy = errors.New("lifecycle lock is already held")
