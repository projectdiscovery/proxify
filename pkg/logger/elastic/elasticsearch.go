package elastic

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"encoding/base64"
	"encoding/json"

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
	url            string
	authentication string
	httpClient     *http.Client
}

// New creates and returns a new client for elasticsearch
func New(option *Options) (*Client, error) {

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: option.SSLVerification},
		},
	}
	// preparing url for elasticsearch
	scheme := "http://"
	if option.SSL {
		scheme = "https://"
	}
	// if authentication is required
	var authentication string
	if len(option.Username) > 0 && len(option.Password) > 0 {
		auth := base64.StdEncoding.EncodeToString([]byte(option.Username + ":" + option.Password))
		auth = "Basic " + auth
		authentication = auth
	}
	url := fmt.Sprintf("%s%s/%s/_update/", scheme, option.Addr, option.IndexName)

	ei := &Client{
		url:            url,
		authentication: authentication,
		httpClient:     httpClient,
	}
	return ei, nil
}

// Store stores a passed log event in elasticsearch
func (c *Client) Store(data types.OutputData) error {
	req, err := http.NewRequest(http.MethodPost, c.url+data.Name, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	if len(c.authentication) > 0 {
		req.Header.Add("Authorization", c.authentication)
	}
	req.Header.Add("Content-Type", "application/json")
	var d map[string]interface{}
	if data.Userdata.HasResponse {
		d = map[string]interface{}{
			"response":  data.DataString,
			"timestamp": time.Now().Format(time.RFC3339),
		}
	} else {
		d = map[string]interface{}{
			"request":   data.DataString,
			"timestamp": time.Now().Format(time.RFC3339),
		}
	}

	b, err := json.Marshal(&map[string]interface{}{
		"doc":           d,
		"doc_as_upsert": true,
	})
	if err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(b))
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.New(err.Error() + "error thrown by elasticsearch " + string(b))
	}
	if res.StatusCode >= 300 {
		return errors.New("elasticsearch responded with an error: " + string(b))
	}
	return nil
}

// Close closes the exporter after operation
func (c *Client) Close() error {
	return nil
}
