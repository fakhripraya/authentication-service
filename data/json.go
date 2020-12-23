package data

import (
	"encoding/json"
	"io"
)

// ToJSON serializes the given interface into a string based JSON format
func ToJSON(payload interface{}, writer io.Writer) error {
	e := json.NewEncoder(writer)

	return e.Encode(payload)
}

// FromJSON deserializes the object from JSON string
// in an io.Reader to the given interface
func FromJSON(payload interface{}, reader io.Reader) error {
	d := json.NewDecoder(reader)

	return d.Decode(payload)
}
