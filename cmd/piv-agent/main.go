package main

import (
	"github.com/alecthomas/kong"
	"go.uber.org/zap"
)

var (
	version string
	date    string
)

// CLI represents the command-line interface.
type CLI struct {
	Debug bool     `kong:"help='Enable debug logging'"`
	Serve ServeCmd `kong:"cmd,default=1,help='(default) Listen for signing requests'"`
	Setup SetupCmd `kong:"cmd,help='Set up the security key for use with SSH'"`
	List  ListCmd  `kong:"cmd,help='List SSH keys available on each security key'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	// init logger
	var log *zap.Logger
	var err error
	if cli.Debug {
		log, err = zap.NewDevelopment()
	} else {
		log, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}
	defer log.Sync() //nolint:errcheck
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(log))
}
