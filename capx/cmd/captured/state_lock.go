package main

import "github.com/hquip/capx/internal/runtimecfg"

func acquireStateDirLock(stateDir, generation string) (func(), error) {
	return runtimecfg.AcquireStateDirLock(stateDir, generation)
}
