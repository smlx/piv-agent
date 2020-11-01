# PIV Agent

An SSH agent which you can use with your PIV smartcard / security key.

`piv-agent` is based almost entirely on ideas from https://github.com/FiloSottile/yubikey-agent.

## What is wrong with yubikey-agent?

Nothing!
I just wanted to gain a better understanding of how the PIV applet on security keys works, and how the Go ssh-agent library works.
I also added a couple of features that I wanted that yubikey-agent lacks, such as:

* support for multiple security keys
* support for multiple slots in those keys
* support for multiple touch policies
* a way to list existing SSH keys
* systemd socket activation

## Philosophy

This agent should require no interaction and in general do the right thing when security keys are plugged/unplugged, laptop is power cycled, etc.

It is highly opinionated:

* Only supports elliptic curve crypto
* Only supports 256-bit EC keys

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

The dbus variable is required for `pinentry` to use a graphical prompt.

```
go build ./cmd/piv-agent && systemd-socket-activate -l /tmp/piv-agent.sock -E DBUS_SESSION_BUS_ADDRESS ./piv-agent serve --debug
```

Then in another terminal:

```
export SSH_AUTH_SOCK=/tmp/piv-agent.sock
ssh ...
```
