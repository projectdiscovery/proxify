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
