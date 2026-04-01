// Package main implements the piv-agent CLI.
package main

import (
	"github.com/alecthomas/kong"
	"go.uber.org/zap"
)

// CLI represents the command-line interface.
type CLI struct {
	Debug   bool       `kong:"help='Enable debug logging'"`
	Serve   ServeCmd   `kong:"cmd,default=1,help='(default) Listen for ssh-agent and gpg-agent requests'"`
	Setup   SetupCmd   `kong:"cmd,help='Configure a security key device for use with piv-agent'"`
	Status  StatusCmd  `kong:"cmd,help='Show the setup status of the PIV applet slots used by piv-agent'"`
	Version VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli, kong.UsageOnError())
	// init logger
	var log *zap.Logger
	var err error
	if cli.Debug {
		log, err = zap.NewDevelopment(zap.AddStacktrace(zap.ErrorLevel))
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
