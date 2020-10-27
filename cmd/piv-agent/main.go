package main

import (
	"github.com/alecthomas/kong"
)

var (
	version   string
	buildTime string
)

// CLI represents the command-line interface.
type CLI struct {
	Listen ListenCmd `kong:"cmd,default=1,help='Listen for signing requests on the SSH_AUTH sock'"`
	Setup  SetupCmd  `kong:"cmd,help='Set up the security key for use with SSH. By default a single SSH key with touch policy cached is generated.'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	kctx.FatalIfErrorf(kctx.Run())
}
