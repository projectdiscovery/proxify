package kafka

import (
	"github.com/Shopify/sarama"
)

// Options required for kafka
type Options struct {
	// Address for kafka instance
	Addr string `yaml:"addr"`
	// Topic to produce messages to
	Topic string `yaml:"topic"`
}

// Server for Kafka
type Client struct {
	producer sarama.SyncProducer
	topic    string
}

// New creates and returns a new client for kafka
func New(option *Options) (*Client, error) {

	config := sarama.NewConfig()
	// Wait for all in-sync replicas to ack the message
	config.Producer.RequiredAcks = sarama.WaitForAll
	// Retry up to 10 times to produce the message
	config.Producer.Retry.Max = 10

	producer, err := sarama.NewSyncProducer([]string{option.Addr}, config)
	if err != nil {
		return nil, err
	}
	ksrvr := &Client{
		producer: producer,
		topic:    option.Topic,
	}
	return ksrvr, nil
}

// Store passes the message to kafka
func (c *Client) Store(data string) error {
	msg := &sarama.ProducerMessage{
		Topic: c.topic,
		Value: sarama.StringEncoder(data),
	}

	_, _, err := c.producer.SendMessage(msg)
	if err != nil {
		return err
	}
	return nil
}

// Close closes the client
func (c *Client) Close() error {
	return c.producer.Close()
}
