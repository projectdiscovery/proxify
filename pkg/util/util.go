package util

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

// HTTPRequestToMap Converts HTTP Request to Matcher Map
func HTTPRequestToMap(req *http.Request) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	var headers string
	for k, v := range req.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		vv := strings.Join(v, " ")
		m[k] = strings.Join(v, " ")
		headers += fmt.Sprintf("%s: %s", k, vv)
	}

	m["all_headers"] = headers

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	m["body"] = string(body)

	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	reqdumpString := string(reqdump)
	m["raw"] = reqdumpString
	m["request"] = reqdumpString
	m["method"] = req.Method
	m["path"] = req.URL.Path
	m["host"] = req.URL.Host
	m["scheme"] = req.URL.Scheme
	m["url"] = req.URL.String()
	m["query"] = req.URL.Query().Encode()

	return m, nil
}

// HTTPResponseToMap Converts HTTP Response to Matcher Map
func HTTPResponseToMap(resp *http.Response) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	m["content_length"] = resp.ContentLength
	m["status_code"] = resp.StatusCode
	var headers string
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		vv := strings.Join(v, " ")
		m[k] = vv
		headers += fmt.Sprintf("%s: %s", k, vv)
	}
	m["all_headers"] = headers

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))
	m["body"] = string(body)

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		responseString := string(r)
		m["raw"] = responseString
		m["response"] = responseString
	}

	return m, nil
}

// MatchAnyRegex checks if data matches any pattern
func MatchAnyRegex(regexes []string, data string) bool {
	for _, regex := range regexes {
		if ok, err := regexp.MatchString(regex, data); err == nil && ok {
			return true
		}
	}
	return false
}

// EvalBoolSlice evaluates a slice of bools using a logical AND
func EvalBoolSlice(slice []bool) bool {
	if len(slice) == 0 {
		return false
	}
	result := slice[0]
	for _, b := range slice {
		result = result && b
	}
	return result
}
