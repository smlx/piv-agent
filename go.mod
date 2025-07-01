module github.com/smlx/piv-agent

go 1.23.2

toolchain go1.24.1

require (
	filippo.io/nistec v0.0.3
	github.com/ProtonMail/go-crypto v0.0.0-20230316153859-cb82d937a5d9
	github.com/alecthomas/kong v1.12.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/gen2brain/beeep v0.11.1
	github.com/go-piv/piv-go/v2 v2.3.0
	github.com/smlx/fsm v0.2.1
	github.com/twpayne/go-pinentry-minimal v0.0.0-20220113210447-2a5dc4396c2a
	github.com/x13a/go-launch v0.0.0-20210715084817-fd409384939b
	go.uber.org/mock v0.5.2
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.39.0
	golang.org/x/sync v0.15.0
	golang.org/x/term v0.32.0
)

require (
	git.sr.ht/~jackmordaunt/go-toast v1.1.2 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/esiqveland/notify v0.13.3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/jackmordaunt/icns/v3 v3.0.1 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/sergeymakinen/go-bmp v1.0.0 // indirect
	github.com/sergeymakinen/go-ico v1.0.0-beta.0 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/ProtonMail/go-crypto => github.com/smlx/go-crypto v0.0.0-20230324130354-fc893cd601c2
