package util

import (
	"bytes"
	"encoding/json"
)

func MarshalStuff(customStruct interface{}) (*bytes.Reader, error) {
	//Marshal data back to JSON
	jsonBody, err := json.Marshal(customStruct)
	if err != nil {
		return nil, err
	}
	bodyReader := bytes.NewReader(jsonBody)

	return bodyReader, err
}
