package main

import (
	"github.com/alecthomas/kong"
	"go.uber.org/zap"
)

var (
	date        string
	goVersion   string
	shortCommit string
	version     string
)

// CLI represents the command-line interface.
type CLI struct {
	Debug      bool          `kong:"help='Enable debug logging'"`
	Serve      ServeCmd      `kong:"cmd,default=1,help='(default) Listen for signing requests'"`
	Setup      SetupCmd      `kong:"cmd,help='Set up the hardware security key for use with piv-agent'"`
	SetupSlots SetupSlotsCmd `kong:"cmd,help='Set up a single slot on the hardware security key PIV applet'"`
	List       ListCmd       `kong:"cmd,help='List cryptographic keys available on each hardware security key'"`
	Version    VersionCmd    `kong:"cmd,help='Print version information'"`
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
