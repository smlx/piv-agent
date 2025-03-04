module github.com/smlx/piv-agent

go 1.23.2

require (
	filippo.io/nistec v0.0.3
	github.com/ProtonMail/go-crypto v0.0.0-20230316153859-cb82d937a5d9
	github.com/alecthomas/kong v1.8.1
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/gen2brain/beeep v0.0.0-20200526185328-e9c15c258e28
	github.com/go-piv/piv-go/v2 v2.3.0
	github.com/smlx/fsm v0.2.1
	github.com/twpayne/go-pinentry-minimal v0.0.0-20220113210447-2a5dc4396c2a
	github.com/x13a/go-launch v0.0.0-20210715084817-fd409384939b
	go.uber.org/mock v0.5.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.35.0
	golang.org/x/sync v0.11.0
	golang.org/x/term v0.29.0
)

require (
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/go-toast/toast v0.0.0-20190211030409-01e6764cf0a4 // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/gopherjs/gopherjs v0.0.0-20181017120253-0766667cb4d1 // indirect
	github.com/gopherjs/gopherwasm v1.1.0 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/ProtonMail/go-crypto => github.com/smlx/go-crypto v0.0.0-20230324130354-fc893cd601c2
