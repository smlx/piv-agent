module github.com/smlx/piv-agent

go 1.15

replace github.com/gopasspw/gopass => github.com/smlx/gopass v1.10.2-0.20201102052721-ffa5b7eadefc

require (
	github.com/alecthomas/kong v0.2.11
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/gen2brain/beeep v0.0.0-20200526185328-e9c15c258e28
	github.com/go-piv/piv-go v1.6.0
	github.com/gopasspw/gopass v1.10.1
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
)
