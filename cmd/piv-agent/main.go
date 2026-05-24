// Package main implements the piv-agent CLI.
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
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
	var log *slog.Logger
	if cli.Debug {
		log = slog.New(slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}

	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(log))
}
