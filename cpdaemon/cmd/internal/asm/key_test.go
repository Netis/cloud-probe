package asm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVKey(t *testing.T) {
	assert.Equal(t, "cpm.base_url", VKey.Cpm.BaseUrl)
	assert.Equal(t, "cpm.worker.memory.policy", VKey.Cpm.Worker.Memory.Policy)
}

// Every leaf key in a shipped example config must be a key cpdaemon reads; a misspelled key is
// otherwise ignored without a warning.
func TestExampleConfigKeysAreRead(t *testing.T) {
	known := map[string]bool{}
	collectVKeys(reflect.ValueOf(VKey), known)

	files, err := filepath.Glob("../../../examples/*.json")
	require.NoError(t, err)
	files = append(files, "../../testdata/config.json")
	require.Greater(t, len(files), 1)

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			var doc map[string]any
			require.NoError(t, json.Unmarshal(data, &doc))

			var unknown []string
			for _, key := range leafKeys(doc, "") {
				if !known[key] {
					unknown = append(unknown, key)
				}
			}
			sort.Strings(unknown)
			assert.Empty(t, unknown, "keys not read by cpdaemon")
		})
	}
}

func collectVKeys(v reflect.Value, keys map[string]bool) {
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			keys[fv.String()] = true
		case reflect.Struct:
			collectVKeys(fv, keys)
		}
	}
}

func leafKeys(m map[string]any, prefix string) []string {
	var keys []string
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			keys = append(keys, leafKeys(sub, prefix+k+".")...)
		} else {
			keys = append(keys, prefix+k)
		}
	}
	return keys
}
