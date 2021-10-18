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

// New creates and returns a new exporter for elasticsearch
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
	url := fmt.Sprintf("%s%s/%s/_doc", scheme, option.Addr, option.IndexName)

	ei := &Client{
		url:            url,
		authentication: authentication,
		httpClient:     httpClient,
	}
	return ei, nil
}

// Export exports a passed result event to elasticsearch
func (c *Client) Store(data string) error {
	// creating a request
	req, err := http.NewRequest(http.MethodPost, c.url, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	if len(c.authentication) > 0 {
		req.Header.Add("Authorization", c.authentication)
	}
	req.Header.Add("Content-Type", "application/json")

	d := map[string]interface{}{
		"Event":     data,
		"Timestamp": time.Now().Format(time.RFC3339),
	}
	b, err := json.Marshal(&d)
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
