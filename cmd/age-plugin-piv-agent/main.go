package main

import (
	"github.com/alecthomas/kong"
)

type CLI struct {
	AgePlugin string     `kong:"name='age-plugin',help='age plugin state machine',enum='recipient-v1,identity-v1,',default=''"`
	Serve     ServeCmd   `kong:"cmd,default='1',help='Listen for age plugin requests'"`
	Version   VersionCmd `kong:"cmd,help='Print version information'"`
}

func main() {
	var cli CLI
	kctx := kong.Parse(&cli, kong.UsageOnError())
	kctx.FatalIfErrorf(kctx.Run())
}
