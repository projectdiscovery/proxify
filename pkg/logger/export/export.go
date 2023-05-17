package export

import (
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
)

type Config struct {
	MaxSize int              `yaml:"max-size,omitempty"`
	Elastic *elastic.Options `yaml:"elastic,omitempty"`
	Kafka   *kafka.Options   `yaml:"kafka,omitempty"`
}
