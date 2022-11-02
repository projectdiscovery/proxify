package swaggergen

import (
	"encoding/json"
	"io"
)

// Schema represents a schema in the spec
type Schema struct {
	Type        string             `json:"type" yaml:"type"`
	Properties  map[string]*Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Description string             `json:"description" yaml:"description,omitempty"`
}

func NewSchema(reader io.Reader) *Schema {
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil
	}
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	dataType := InterfaceToType(data)
	// generate shema from data map
	schema := &Schema{
		Type: dataType,
	}
	if dataType == "object" {
		schema.Properties = make(map[string]*Schema)
		for key, value := range data.(map[string]interface{}) {
			schema.Properties[key] = &Schema{
				Type: InterfaceToType(value),
			}
		}
	}
	return schema
}

func InterfaceToType(data interface{}) string {
	switch data.(type) {
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	default:
		return "notfound"
	}
}
