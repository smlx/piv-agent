module github.com/smlx/piv-agent

go 1.25.0

require (
	filippo.io/age v1.3.1
	filippo.io/hpke v0.4.0
	filippo.io/nistec v0.0.4
	github.com/ProtonMail/go-crypto v0.0.0-20230316153859-cb82d937a5d9
	github.com/alecthomas/kong v1.15.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/esiqveland/notify v0.13.3
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/smlx/fsm v0.2.1
	github.com/twpayne/go-pinentry-minimal v0.0.0-20220113210447-2a5dc4396c2a
	go.uber.org/mock v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.52.0
	golang.org/x/sync v0.20.0
	golang.org/x/term v0.43.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dmarkham/enumer v1.6.1 // indirect
	github.com/pascaldekloe/name v1.0.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

replace github.com/ProtonMail/go-crypto => github.com/smlx/go-crypto v0.0.0-20230324130354-fc893cd601c2

tool (
	github.com/dmarkham/enumer
	go.uber.org/mock/mockgen
)

replace go.uber.org/mock => github.com/smlx/mock v0.0.0-20260505154527-3c1231001ced
