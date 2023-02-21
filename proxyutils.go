package proxify

// Proxy Utils are
import (
	"regexp"

	"github.com/projectdiscovery/gologger"
)

var (
	inScopePoolRegex    = []*regexp.Regexp{}
	outOfScopePoolRegex = []*regexp.Regexp{}
	hasInScopeFilter    = false
	hasOutOfScopeFilter = false
)

// SetupRegex Initializes InScope and OutOfScope Filters
func SetupRegex(inscope, outofscope []string) {
	if len(inscope) > 0 {
		for _, v := range inscope {
			re := regexp.MustCompile(v)
			inScopePoolRegex = append(inScopePoolRegex, re)
		}
	}
	if len(outofscope) > 0 {
		for _, v := range outofscope {
			re := regexp.MustCompile(v)
			outOfScopePoolRegex = append(outOfScopePoolRegex, re)
		}
	}

	hasInScopeFilter = len(inScopePoolRegex) != 0
	hasOutOfScopeFilter = len(outOfScopePoolRegex) != 0

	gologger.Info().Msgf("Starting Proxy with %v Inscope and %v OutofScope Filters", len(inScopePoolRegex), len(outOfScopePoolRegex))
}

// isIntercepted is top/level scope filter that filters out domains if not supported
// other dsl filters are only run if this is successful
func isIntercepted(url string) bool {
	if !hasInScopeFilter && !hasOutOfScopeFilter {
		return true
	}
	var intercepStatus bool
	if hasInScopeFilter {
		for _, v := range inScopePoolRegex {
			if !intercepStatus {
				intercepStatus = v.MatchString(url)
			} else {
				break
			}
		}
	} else {
		// if there are no inscope regex we depend on outofscope for matching
		// althought this is not a efficient way to filter out request we support it
		intercepStatus = true
	}

	if hasOutOfScopeFilter {
		for _, v := range outOfScopePoolRegex {
			if intercepStatus && v.MatchString(url) {
				intercepStatus = false
			}
		}
	}
	return intercepStatus
}
