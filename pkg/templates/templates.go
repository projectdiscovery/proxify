package templates

import (
	"os"

	"github.com/projectdiscovery/proxify/internal/runner"
	"gopkg.in/yaml.v2"
)

type Template struct {
	Proxy Proxy `yaml:"proxy"`
}

type Proxy struct {
	HTTPAddr string `yaml:"http-addr"`
}

func Parse(templatePath string) (*runner.Options, error) {
	file, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	var template Template
	err = yaml.Unmarshal(file, &template)
	if err != nil {
		return nil, err
	}

	options := &runner.Options{
		ListenAddrHTTP: template.Proxy.HTTPAddr,
	}

	return options, nil
}
