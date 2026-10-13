package cpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// splitArgs splits a strategy's startup string like a shell: runs of spaces separate
// arguments, quotes group them.
func Test_splitArgs(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"   ", nil},
		{"-s 65535 -t 0", []string{"-s", "65535", "-t", "0"}},
		{"  -s   65535  ", []string{"-s", "65535"}},
		{`-B "eth 1" -M 'do'`, []string{"-B", "eth 1", "-M", "do"}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := splitArgs(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := splitArgs(`-B "eth1`)
	assert.ErrorContains(t, err, "unclosed quote")
}
