package runner

import (
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

// Version is the current version
const version = `v0.0.16`

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
