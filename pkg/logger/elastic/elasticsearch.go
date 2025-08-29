package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// Options contains necessary options required for elasticsearch communicaiton
type Options struct {
	// Address for elasticsearch instance
	Addr string `yaml:"addr"`
	// SSL enables ssl for elasticsearch connection
	SSL bool `yaml:"ssl"`
	// SSLVerification disables SSL verification for elasticsearch
	SSLVerification bool `yaml:"ssl-verification"`
	// Username for the elasticsearch instance
	Username string `yaml:"username"`
	// Password is the password for elasticsearch instance
	Password string `yaml:"password"`
	// IndexName is the name of the elasticsearch index
	IndexName string `yaml:"index-name"`
}

// Client type for elasticsearch
type Client struct {
	index    string
	options  *Options
	esClient *elasticsearch.Client
}

// New creates and returns a new client for elasticsearch
func New(option *Options) (*Client, error) {
	scheme := "http://"
	if option.SSL {
		scheme = "https://"
	}

	elasticsearchClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{scheme + option.Addr},
		Username:  option.Username,
		Password:  option.Password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: option.SSLVerification,
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "error creating elasticsearch client")
	}
	client := &Client{
		esClient: elasticsearchClient,
		index:    option.IndexName,
		options:  option,
	}
	return client, nil

}

// Store saves a passed log event in elasticsearch
func (c *Client) Save(data types.HTTPTransaction) error {
	var doc map[string]interface{}
	if data.Userdata.HasResponse {
		doc = map[string]interface{}{
			"response":  data.DataString,
			"timestamp": time.Now().Format(time.RFC3339),
		}
	} else {
		doc = map[string]interface{}{
			"request":   data.DataString,
			"timestamp": time.Now().Format(time.RFC3339),
		}
	}

	body, err := json.Marshal(&map[string]interface{}{
		"doc":           doc,
		"doc_as_upsert": true,
	})
	if err != nil {
		return err
	}
	updateRequest := esapi.UpdateRequest{
		Index:      c.index,
		DocumentID: data.Name,
		Body:       bytes.NewReader(body),
	}
	res, err := updateRequest.Do(context.Background(), c.esClient)
	if err != nil || res == nil {
		return errors.New("error thrown by elasticsearch: " + err.Error())
	}
	if res.StatusCode >= 300 {
		return errors.New("elasticsearch responded with an error: " + string(res.String()))
	}
	// Drain response to reuse connection
	_, er := io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return er
}
