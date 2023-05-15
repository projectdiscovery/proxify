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
	Timestamp string `json:"timestamp"`
	URL       string `json:"url"`
	Request   struct {
		Header map[string]string `json:"header"`
		Body   string            `json:"body"`
		Raw    string            `json:"raw"`
	} `json:"request"`
	Response struct {
		Header map[string]string `json:"header"`
		Body   string            `json:"body"`
		Raw    string            `json:"raw"`
	} `json:"response"`
}
