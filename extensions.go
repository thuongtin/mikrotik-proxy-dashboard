//go:build !private

package main

import (
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	internalweb "github.com/thuongtin/mikrotik-proxy-dashboard/internal/web"
)

// extensions holds the optional features of an edition. The core edition
// has none.
type extensions struct{}

// loadExtensions reads the extensions' settings. It runs before any child
// process starts.
func loadExtensions(*config.Config) *extensions { return &extensions{} }

// start runs the extensions once the web server exists. The returned
// function stops them; it runs before sing-box stops.
func (e *extensions) start(*internalweb.Server) (stop func()) { return func() {} }
