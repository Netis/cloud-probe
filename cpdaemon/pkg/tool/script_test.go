package tool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunShellScript(t *testing.T) {
	t.Run("hello", func(t *testing.T) {
		got, err := RunShellScript("testdata/hello.sh")
		require.NoError(t, err)
		assert.Equal(t, "hello\n", got)
	})

	t.Run("error", func(t *testing.T) {
		_, err := RunShellScript("testdata/error.sh")
		require.Error(t, err)
		t.Log(err)
	})
}
