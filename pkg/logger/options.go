package logger

import (
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
)

// Config is a configuration file for proxify logger module
type Config struct {
	Kafka   kafka.Options   `yaml:"kafka"`
	Elastic elastic.Options `yaml:"elastic"`
}
