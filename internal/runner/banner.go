package runner

import (
	"runtime/debug"

	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
                       _ ___    
   ___  _______ __ __ (_) _/_ __
  / _ \/ __/ _ \\ \ // / _/ // /
 / .__/_/  \___/_\_\/_/_/ \_, / 
/_/                      /___/
`

// version is the current version. Release builds set it with -ldflags, and
// go install builds fall back to the module version recorded by the toolchain.
var version = "dev"

func init() {
	if bi, ok := debug.ReadBuildInfo(); ok {
		version = resolveVersion(version, bi)
	}
}

// resolveVersion prefers a version injected at link time, then the module
// version recorded by the Go toolchain, and otherwise reports "dev".
func resolveVersion(injected string, bi *debug.BuildInfo) string {
	if injected != "" && injected != "dev" {
		return injected
	}
	if bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates proxify
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("proxify", version)()
	}
}
