package cpm

import (
	"reflect"
	"testing"

	"github.com/samber/lo"
)

func Test_parseStartup(t *testing.T) {
	type args struct {
		startup       string
		ignoreUnknown bool
	}
	tests := []struct {
		name    string
		args    args
		want    *startupArgs
		wantErr bool
	}{
		{
			args: args{
				startup: "",
			},
			want: &startupArgs{},
		},
		{
			args: args{
				startup: "-s 65535 -t 1000",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
				Timeout: lo.ToPtr(1000),
			},
		},
		{
			args: args{
				startup: "--snaplen=65535 --timeout=1000",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
				Timeout: lo.ToPtr(1000),
			},
		},
		{
			args: args{
				startup: "--snaplen 65535",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
			},
		},
		{
			args: args{
				startup: "--snaplen 65535 --unknown=xxx",
			},
			wantErr: true,
		},
		{
			args: args{
				startup:       "--snaplen 65535 --unknown=xxx",
				ignoreUnknown: true,
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStartup(tt.args.startup, tt.args.ignoreUnknown)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseStartup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseStartup() = %v, want %v", got, tt.want)
			}
		})
	}
}
