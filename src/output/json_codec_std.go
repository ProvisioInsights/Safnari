//go:build !jsonv2

package output

import "encoding/json"

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func jsonMarshalIndent(value any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(value, prefix, indent)
}
