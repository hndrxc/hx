package buildinfo

// Version holds the current version of the application.
// It can be overridden at link time using:
//
//	-ldflags "-X github.com/hndrxc/hx/internal/buildinfo.Version=..."
var Version = "dev"
