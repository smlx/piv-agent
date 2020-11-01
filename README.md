# PIV Agent

An SSH agent which you can use with your PIV smartcard / security key.

## Security key support

Tested with:

* YubiKey 5C, firmware 5.2.4

## Platform support

Currently requires Linux and systemd.

## Usage

Currently requires systemd socket activation.

```
// TODO
```

## Testing

```
go build ./cmd/piv-agent && systemd-socket-activate -l /tmp/piv-agent.sock ./piv-agent
```
