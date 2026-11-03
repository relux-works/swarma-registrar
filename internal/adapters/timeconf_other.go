//go:build !linux

package adapters

import "context"

func NewProductionClock(context.Context, string) (*Clock, <-chan struct{}, func(), error) {
	return nil, nil, nil, failure("clock_skew")
}
