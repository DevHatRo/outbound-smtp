package main

import (
	"errors"

	"github.com/DevHatRO/outbound-smtp/internal/store"
)

// Replaced as the later build stages land.

func (a *app) serve() error { return errors.New("serve: not implemented yet") }
func (a *app) sendTest(_ *store.Store, _ []string) error {
	return errors.New("send-test: not implemented yet")
}
