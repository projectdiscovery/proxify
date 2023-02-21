package proxify

import (
	"testing"

	stringsutil "github.com/projectdiscovery/utils/strings"
)

func TestInterception(t *testing.T) {
	testcases := []struct {
		Inscope    []string
		OutOfScope []string
		NotAllowed []string
	}{
		{[]string{"scanme"}, []string{}, []string{"example.com"}},
		{[]string{"scanme.sh"}, []string{}, []string{"scanmesh.org", "example.com", "scanme.tld"}},
		{[]string{""}, []string{"example"}, []string{"example.com"}},
		{[]string{"scanme.*"}, []string{"example"}, []string{"example.com"}},
		{[]string{"^(admin)"}, []string{"example"}, []string{"example.com", "admin.scanme.sh"}},
		{[]string{".*iiitp.ac.in"}, []string{""}, []string{"scanme.sh",
			"no.scanme.sh",
			"admin.scanme.sh",
			"scanmesh.org",
			"scanme.tld",
			"scanme.sh/with/path",
			"example.com"}},
	}

	urls := []string{
		"scanme.sh",
		"no.scanme.sh",
		"admin.scanme.sh",
		"scanmesh.org",
		"scanme.tld",
		"scanme.sh/with/path",
		"example.com",
	}

	for _, v := range testcases {
		SetupRegex(v.Inscope, v.OutOfScope)
		for _, url := range urls {
			if !isIntercepted(url) && !stringsutil.EqualFoldAny(url, v.NotAllowed...) {
				t.Errorf("something went wrong %v intercept while it is not allowed for testcase %v", url, v)
			}
		}
	}
}
