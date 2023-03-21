package runner

import (
	"github.com/projectdiscovery/gologger"
)

const banner = `
                       _ ___    
   ___  _______ __ __ (_) _/_ __
  / _ \/ __/ _ \\ \ // / _/ // /
 / .__/_/  \___/_\_\/_/_/ \_, / 
/_/                      /___/
`

// Version is the current version
const Version = `0.0.9`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}
