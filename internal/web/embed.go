// Package web embeds the static admin dashboard assets.
package web

import "embed"

//go:embed static/*
var StaticFS embed.FS

// StaticDir returns the virtual subdirectory containing the dashboard assets.
const StaticDir = "static"
