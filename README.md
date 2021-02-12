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
* socket activation (systemd-compatible)
* support loading key files from disk

## Philosophy

This agent should require no interaction and in general do the right thing when security keys are plugged/unplugged, laptop is power cycled, etc.

It is highly opinionated:

* Only supports elliptic curve crypto
* Only supports 256-bit EC keys on hardware tokens
* Only supports ed25519 ssh keys on disk
* Assumes socket activation

## Security key support

Tested with:

* YubiKey 5C, firmware 5.2.4

## Platform support

Currently tested on Linux and systemd.

## Usage

### Setup

Currently requires systemd socket activation.
Similar configuration may be possible on macOS(?? if you know how to do this please open an issue or PR!)

`piv-agent.service` looks for `$HOME/go/bin/piv-agent` by default.
If the binary is in a different location you'll have to edit the service file.

```
cp deploy/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable piv-agent.socket
systemctl --user start piv-agent.socket
```

### Prefer the SSH keys on the hardware token

`piv-agent` supports loading SSH keys from disk.
However to prefer the keys on the hardware token (to present these to the server first) it must be configured in SSH config.

To do this, copy the public key to e.g. `~/.ssh/id_pivTouchCached.pub`, and add this line to your SSH config:

```
IdentityFile ~/.ssh/id_pivTouchCached
```

### PIN / Passphrase caching

`piv-agent` is designed to minimise the need to store secret keys permanently in memory while also being highly usable:

* it takes a persistent transaction on the hardware token, effectively caching the PIN.
* it also caches passphrases for on-disk keys (i.e. `~/.ssh/id_ed25519`).

After a period of inactivity (32 min by default) it exits, dropping both of these.
Socket activation restarts it automatically.

I recommend using the pinentry option to store the PIN, but not the passphrase.
This somewhat addresses the threat model of someone accessing your laptop left unlocked in a cafe, but of course it doesn't address keyloggers etc.
It also has the advantage of ensuring that you don't forget your passphrase.
But you might forget your PIN, so maybe don't store that either if you're concerned about that possibility? 🤷

## Building / Testing

The dbus variable is required for `pinentry` to use a graphical prompt.

```
go build ./cmd/piv-agent && systemd-socket-activate -l /tmp/piv-agent.sock -E DBUS_SESSION_BUS_ADDRESS ./piv-agent serve --debug
```

Then in another terminal:

```
export SSH_AUTH_SOCK=/tmp/piv-agent.sock
ssh ...
```
