package cmd

import "testing"

func TestNormalizeFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"text", "text", false},
		{"TEXT", "text", false},
		{"jsonl", "jsonl", false},
		{"JSONL", "jsonl", false},
		{"ndjson", "jsonl", false},
		{"NDJSON", "jsonl", false},
		{"", "", true},
		{"yaml", "yaml", true},
		{"json", "json", true}, // not "jsonl"; we don't auto-promote
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := c.in
			err := NormalizeFormat(&got)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRequireUnix(t *testing.T) {
	orig := Globals.Unix
	defer func() { Globals.Unix = orig }()

	Globals.Unix = ""
	if err := requireUnix(); err == nil {
		t.Fatal("expected error when --unix is empty")
	}

	Globals.Unix = "/tmp/sock"
	if err := requireUnix(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
