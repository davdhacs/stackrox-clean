package version

// Version variables with fallback defaults for ad-hoc builds.
// When building via the scanner Makefile, these are overridden
// by the generated zversion.go init() function.

// Version is the scanner version (from the latest git tag).
var Version string

// VulnerabilityVersion is the supported vulnerability schema version.
var VulnerabilityVersion string
