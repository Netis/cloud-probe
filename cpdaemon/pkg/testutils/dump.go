package testutils

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

func DumpResultToJSON(fixture string, result any) error {
	fp, err := os.Create(fixture)
	if err != nil {
		return errors.WithStack(err)
	}
	defer fp.Close()

	enc := json.NewEncoder(fp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func LoadResultFromJSON(fixture string, result any) error {
	fp, err := os.Open(fixture)
	if err != nil {
		return errors.WithStack(err)
	}
	defer fp.Close()

	err = json.NewDecoder(fp).Decode(result)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
