# PIV Agent

![Tag and Release](https://github.com/smlx/piv-agent/workflows/Tag%20and%20release%20on%20merge/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/smlx/piv-agent/badge.svg?branch=main)](https://coveralls.io/github/smlx/piv-agent?branch=main)

## About

An SSH agent which you can use with your PIV smartcard / security key.

`piv-agent` is based almost entirely on ideas and cryptography from https://github.com/FiloSottile/yubikey-agent.

**IMPORTANT NOTE**: I am not a cryptographer and I make no assertion about the security or otherwise of this software.

### What is wrong with yubikey-agent?

Nothing!
I just wanted to gain a better understanding of how the PIV applet on security keys works, and how the Go ssh-agent library works.
I also added a couple of features that I wanted that yubikey-agent lacks, such as:

* support for multiple security keys
* support for multiple slots in those keys
* support for multiple touch policies
* a way to list existing SSH keys
* support loading key files from disk
* socket activation (systemd-compatible)
  * as a result, automatically drop the transaction on the security key after some period of disuse

### Philosophy

This agent should require no interaction and in general do the right thing when security keys are plugged/unplugged, laptop is power cycled, etc.

It is highly opinionated:

* Only supports elliptic curve crypto
* Only supports 256-bit EC keys on hardware tokens
* Only supports ed25519 ssh keys on disk (`~/.ssh/id_ed25519`)
* Assumes socket activation

### Hardware support

Tested with:

* YubiKey 5C, firmware 5.2.4

### Platform support

Currently tested on Linux and systemd.
The macOS binaries built for releases are experimental, and not tested.

## Install

### Prerequisites

`piv-agent` uses [`piv-go`](https://github.com/go-piv/piv-go#installation), so has dependencies on [`pcsclite`](https://pcsclite.apdu.fr/).

```
# debian/ubuntu
sudo apt install pcscd
```

### `piv-agent`

`piv-agent` currently requires systemd socket activation.
Similar configuration may be possible on macOS (see [issue #12](https://github.com/smlx/piv-agent/issues/12)) or other systems. PRs welcome!

`piv-agent.service` looks for `$HOME/go/bin/piv-agent` by default.
If the binary is in a different location you'll have to edit the service file.

```
cp deploy/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now piv-agent.socket
```

## Set up security key

IMPORTANT NOTE: This procedure generally is only required once per security key, and wipes any existing keys from PIV slots.

By default, `piv-agent` uses three slots on your security key to set up keys with different touch policies: never required, cached (required once per transaction), and always.

```
# find the name of the security keys (cards)
piv-agent list
# generate new keys
piv-agent setup --pin=123456 --card='Yubico YubiKey FIDO+CCID 01 00' --reset-security-key
# view newly generated keys
piv-agent list
```

## Use

Generally, add the SSH key from the security token(s) _and_ the your key file SSH key to all services for redundancy.

### Set `SSH_AUTH_SOCK`

Export the `SSH_AUTH_SOCK` variable in your shell.

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/piv-agent/ssh.socket
```

### Prefer the SSH keys on the hardware token

By default, `ssh` will offer [keyfiles it finds on disk](https://manpages.debian.org/testing/openssh-client/ssh_config.5.en.html#IdentityFile) _before_ those from the agent.
This is a problem because `piv-agent` is designed to offer keys from the hardware token first, and only fall back to local keyfiles if token keys are refused.
To get `ssh` to ignore local keyfiles and only talk to `piv-agent`, add this line to your `ssh_config`.

```
IdentityFile /dev/null
```

### PIN / Passphrase caching

`piv-agent` is designed to minimise the need to store secret keys permanently in memory while also being highly usable:

* it takes a persistent transaction on the hardware token, effectively caching the PIN.
* it also caches passphrases for on-disk keys (i.e. `~/.ssh/id_ed25519`).

After a period of inactivity (32 min by default) it exits, dropping both of these.
Socket activation restarts it automatically as required.

If your pinentry supports storing credentials I recommend storing the PIN, but not the passphrase, as a decent usability/security tradeoff.
This ensures that at least the encrypted key file and its passphrase aren't stored together.
It also has the advantage of ensuring that you don't forget your passphrase.
But you might forget your PIN, so maybe don't store that either if you're concerned about that possibility? 🤷

## Build and Test

`piv-agent` has dependencies through [`piv-go`](https://github.com/go-piv/piv-go#installation).

```
# debian/ubuntu
sudo apt install libpcsclite-dev pcscd
```

The dbus variable is required for `pinentry` to use a graphical prompt.

```
go build ./cmd/piv-agent && systemd-socket-activate -l /tmp/piv-agent.sock -E DBUS_SESSION_BUS_ADDRESS ./piv-agent serve --debug
```

Then in another terminal:

```
export SSH_AUTH_SOCK=/tmp/piv-agent.sock
ssh ...
```
