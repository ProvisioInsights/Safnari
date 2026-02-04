//go:build jsonv2

package output

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

func jsonMarshal(value any) ([]byte, error) {
	return jsonv2.Marshal(value)
}

func jsonMarshalIndent(value any, prefix, indent string) ([]byte, error) {
	opts := jsonv2.JoinOptions(
		jsontext.WithIndent(indent),
		jsontext.WithIndentPrefix(prefix),
	)
	return jsonv2.Marshal(value, opts)
}
