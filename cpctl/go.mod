module github.com/Netis/cloud-probe/cpctl

go 1.24.1

require (
	github.com/Netis/cloud-probe/cpgolib v0.0.0
	github.com/spf13/cobra v1.9.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

replace github.com/Netis/cloud-probe/cpgolib => ../cpgolib
