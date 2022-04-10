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
	Serve      ServeCmd      `kong:"cmd,default=1,help='(default) Listen for ssh-agent and gpg-agent requests'"`
	Setup      SetupCmd      `kong:"cmd,help='Reset the PIV applet to factory settings before configuring it for use with piv-agent'"`
	SetupSlots SetupSlotsCmd `kong:"cmd,help='Set up a single slot on the PIV applet for use with piv-agent. This is for advanced users, most people should use the setup command.'"`
	List       ListCmd       `kong:"cmd,help='List cryptographic keys available on the PIV applet of each hardware security key'"`
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
