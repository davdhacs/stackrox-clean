package internal

import _ "embed"

// Version data is embedded from committed files at the repo root.
// go-tool.sh copies them (stripped of whitespace) into this directory
// before building. ActionIDs only change when file content changes
// (version bumps), not on every commit.

//go:embed VERSION
var MainVersion string

//go:embed COLLECTOR_VERSION
var CollectorVersion string

//go:embed SCANNER_VERSION
var ScannerVersion string

//go:embed FACT_VERSION
var FactVersion string

// GitShortSha is set by the stamp package for dev/CI builds.
var GitShortSha string
