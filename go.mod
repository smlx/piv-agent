module github.com/smlx/piv-agent

go 1.25.0

require (
	filippo.io/age v1.3.1
	filippo.io/hpke v0.4.0
	github.com/alecthomas/kong v1.15.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/esiqveland/notify v0.14.0
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/twpayne/go-pinentry-minimal v0.0.0-20220113210447-2a5dc4396c2a
	go.uber.org/mock v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.53.0
	golang.org/x/sync v0.21.0
	golang.org/x/term v0.44.0
)

require (
	filippo.io/nistec v0.0.4 // indirect
	github.com/dmarkham/enumer v1.6.1 // indirect
	github.com/pascaldekloe/name v1.0.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

tool (
	github.com/dmarkham/enumer
	go.uber.org/mock/mockgen
)

replace go.uber.org/mock => github.com/smlx/mock v0.0.0-20260505154527-3c1231001ced
