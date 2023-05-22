package types

type UserData struct {
	ID          string
	Match       bool
	HasResponse bool
	Host        string
}

type OutputData struct {
	Userdata   UserData
	Data       []byte
	DataString string
	Name       string
	PartSuffix string
	Format     string
}

type HTTPRequestResponseLog struct {
	Timestamp string `json:"timestamp,omitempty"`
	URL       string `json:"url,omitempty"`
	Request   struct {
		Header map[string]string `json:"header,omitempty"`
		Body   string            `json:"body,omitempty"`
		Raw    string            `json:"raw,omitempty"`
	} `json:"request,omitempty"`
	Response struct {
		Header map[string]string `json:"header,omitempty"`
		Body   string            `json:"body,omitempty"`
		Raw    string            `json:"raw,omitempty"`
	} `json:"response,omitempty"`
}
