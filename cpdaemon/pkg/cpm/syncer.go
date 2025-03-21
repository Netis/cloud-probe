package cpm

import "time"

type Syncer struct {
	client   *HttpClient
	interval time.Duration
}
