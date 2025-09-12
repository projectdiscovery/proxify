package proxify

import (
	"net/url"
	"reflect"
	"testing"
)

func TestNewHTTPProxyRoundRobinDialer(t *testing.T) {
	tests := []struct {
		name            string
		upstreamProxies []string
		shouldThrowErr  bool
	}{
		{
			name:            "empty",
			upstreamProxies: []string{},
			shouldThrowErr:  true,
		},
		{
			name:            "one",
			upstreamProxies: []string{"http://localhost:7777"},
			shouldThrowErr:  false,
		},
		{
			name:            "multiple",
			upstreamProxies: []string{"http://localhost:7777", "http://localhost:9999"},
			shouldThrowErr:  false,
		},
		{
			name:            "invalid",
			upstreamProxies: []string{"http://:invalid"},
			shouldThrowErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, actualErr := newHTTPProxyRoundRobinDialer(test.upstreamProxies)
			if (actualErr != nil) != test.shouldThrowErr {
				t.Errorf("newHTTPProxyRoundRobinDialer() actualErr = %v, shouldThrowErr = %v", actualErr, test.shouldThrowErr)
				return
			}
			if !test.shouldThrowErr && actual == nil {
				t.Errorf("newHTTPProxyRoundRobinDialer() actual = %v, expected non-nil", actual)
			}
		})
	}
}

func TestNewSOCKS5ProxyRoundRobinDialer(t *testing.T) {
	tests := []struct {
		name            string
		upstreamProxies []string
		shouldThrowErr  bool
	}{
		{
			name:            "empty",
			upstreamProxies: []string{},
			shouldThrowErr:  true,
		},
		{
			name:            "one",
			upstreamProxies: []string{"socks5://localhost:10070"},
			shouldThrowErr:  false,
		},
		{
			name:            "multiple",
			upstreamProxies: []string{"socks5://localhost:10070", "socks5://localhost:10090"},
			shouldThrowErr:  false,
		},
		{
			name:            "invalid",
			upstreamProxies: []string{"socks5://:invalid"},
			shouldThrowErr:  true,
		},
		{
			name:            "auth",
			upstreamProxies: []string{"socks5://user:pass@localhost:10070"},
			shouldThrowErr:  false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, actualErr := newSOCKS5ProxyRoundRobinDialer(test.upstreamProxies)
			if (actualErr != nil) != test.shouldThrowErr {
				t.Errorf("newSOCKS5ProxyRoundRobinDialer() actualErr = %v, shouldThrowErr = %v", actualErr, test.shouldThrowErr)
				return
			}
			if !test.shouldThrowErr && actual == nil {
				t.Errorf("newSOCKS5ProxyRoundRobinDialer() actual = %v, expected non-nil", actual)
			}
		})
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		urls     []*url.URL
		expected []string
	}{
		{
			name:     "single",
			urls:     []*url.URL{{Scheme: "http", Host: "localhost:8080"}},
			expected: []string{"http://localhost:8080"},
		},
		{
			name: "multiple",
			urls: []*url.URL{
				{Scheme: "http", Host: "localhost:8080"},
				{Scheme: "socks5", User: url.UserPassword("user", "pass"), Host: "localhost:8081"},
			},
			expected: []string{"http://localhost:8080", "socks5://user:pass@localhost:8081"},
		},
		{
			name:     "empty",
			urls:     []*url.URL{},
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := toStringSlice(test.urls); !reflect.DeepEqual(actual, test.expected) {
				t.Errorf("toStringSlice() actual = %v, expected = %v", actual, test.expected)
			}
		})
	}
}
