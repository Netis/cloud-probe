package worker

import (
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_parseLogLine(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name  string
		args  args
		want  time.Time
		want1 slog.Level
		want2 string
		want3 bool
	}{
		{
			args: args{
				line: "2025-04-27T17:52:40  INFO  /root/code/myself/cloud-probe/cpworker/src/main.c:124: listen on unix socket tmp/cpm-worker.sock",
			},
			want:  time.Date(2025, 4, 27, 17, 52, 40, 0, time.Local),
			want1: slog.LevelInfo,
			want2: "/root/code/myself/cloud-probe/cpworker/src/main.c:124: listen on unix socket tmp/cpm-worker.sock",
			want3: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3 := parseLogLine(tt.args.line)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseLogLine() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("parseLogLine() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("parseLogLine() got2 = %v, want %v", got2, tt.want2)
			}
			if got3 != tt.want3 {
				t.Errorf("parseLogLine() got3 = %v, want %v", got3, tt.want3)
			}
		})
	}
}

type testLineOutput struct {
	lines []string
}

func (o *testLineOutput) Write(line string) {
	o.lines = append(o.lines, line)
}

func Test_stdWriter_Write(t *testing.T) {
	o := testLineOutput{}
	w := newPipeWriter(&o)
	w.Write([]byte("2025-04-27T17:52:40  IN"))
	w.Write([]byte("FO  /root/code/myself/cloud-probe/cpworker/src/main.c:124: listen on unix socket\n"))
	w.Write([]byte("use activate_mmap\n"))
	w.Write([]byte("2025-04-27T17:52:41  INFO /home/timmy/code/netis/cloud-probe/cloud-probe/cpworker/src/main.c:113: set cpu affinity to 1\n2025-04-27T17:52:42"))
	w.Write([]byte("  WARN test\n"))
	assert.Equal(t, []string{
		"2025-04-27T17:52:40  INFO  /root/code/myself/cloud-probe/cpworker/src/main.c:124: listen on unix socket",
		"use activate_mmap",
		"2025-04-27T17:52:41  INFO /home/timmy/code/netis/cloud-probe/cloud-probe/cpworker/src/main.c:113: set cpu affinity to 1",
		"2025-04-27T17:52:42  WARN test",
	}, o.lines)
}
