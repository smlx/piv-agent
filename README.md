# PIV Agent

![Tag and Release](https://github.com/smlx/piv-agent/workflows/Tag%20and%20release%20on%20merge/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/smlx/piv-agent/badge.svg?branch=main)](https://coveralls.io/github/smlx/piv-agent?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/smlx/piv-agent)](https://goreportcard.com/report/github.com/smlx/piv-agent)

## About

* `piv-agent` is a replacement for `ssh-agent` and `gpg-agent` which you can use with your smartcard or security key that implements [PIV](https://csrc.nist.gov/projects/piv/piv-standards-and-supporting-documentation) (e.g. a [Yubikey](https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html)).
* `piv-agent` originated as a reimplementation of [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) because I wanted a couple of extra features and also to gain a better understanding of the PIV applet on security keys, and the Go [`x/crypto/ssh/agent`](https://pkg.go.dev/golang.org/x/crypto/ssh/agent) package. It has since grown in features (good) and complexity (bad).
* `piv-agent` is built on Go standard library and supplementary `crypto` packages, as well as [`piv-go`](https://github.com/go-piv/piv-go/) and [`pcsclite`](https://pcsclite.apdu.fr/). Thanks for the great software!

---
**DISCLAIMER**

I make no assertion about the security or otherwise of this software and I am not a cryptographer.
If you are, please take a look at the code and send PRs or issues. :green_heart:

---

### Some features of piv-agent

* implements (a subset of) both `ssh-agent` and `gpg-agent` functionality
* support for multiple security keys
* support for multiple slots in those keys
* support for multiple touch policies
* list existing keys on a security key in SSH and OpenPGP format
* socket activation (systemd-compatible)
  * as a result, automatically drop the transaction on the security key and cached passphrases after some period of disuse
* provides "fall-back" to traditional SSH and OpenPGP keyfiles

### Design philosophy

This agent should require no interaction and in general do the right thing when security keys are plugged/unplugged, laptop is power cycled, etc.

It is highly opinionated:

* Only supports 256-bit EC keys on hardware tokens
* Only supports ed25519 SSH keys on disk (`~/.ssh/id_ed25519`)
* Requires socket activation

It makes some concession to practicality with OpenPGP:

* Supports RSA signing and decryption for OpenPGP keyfiles.
  RSA OpenPGP keys are widespread and Debian in particular [only documents RSA keys](https://wiki.debian.org/Keysigning).

It tries to strike a balance between security and usability:

* Takes a persistent transaction on the hardware token, effectively caching the PIN.
* Caches passphrases for on-disk keys (i.e. `~/.ssh/id_ed25519`) in memory, so these only need to be provided once after the agent starts.
* After a period of inactivity (32 minutes by default) it exits, dropping both of these.
  Socket activation restarts it automatically as required.

### Hardware support

Tested with:

* [YubiKey 5C](https://www.yubico.com/au/product/yubikey-5c/), firmware 5.2.4

Will be tested with (once it ships!):

* [Solo V2](https://www.kickstarter.com/projects/conorpatrick/solo-v2-safety-net-against-phishing/)

Any device implementing the SCard API (PC/SC), and supported by [`piv-go`](https://github.com/go-piv/piv-go/) / [`pcsclite`](https://pcsclite.apdu.fr/) may work.
If you have tested another device with `piv-agent` successfully, please send a PR adding it to this list.

### Platform support

Currently tested on Linux with `systemd`.

If you have a Mac, I'd love to add support for `launchd` socket activation. See issue https://github.com/smlx/piv-agent/issues/12.

### Protocol / Encryption Algorithm support

| Supported | Not Supported | Support Planned (maybe) |
| ---       | ---           | ---                     |
| ✅        | ❌            | ⏳                      |

#### ssh-agent

|                     | Security Key | Keyfile |
| ---                 | ---          | ---     |
| ecdsa-sha2-nistp256 | ✅           | ❌      |
| ssh-ed25519         | ⏳           | ✅      |


#### gpg-agent

|                         | Security Key | Keyfile |
| ---                     | ---          | ---     |
| ECDSA Sign (NIST P-256) | ✅           | ✅      |
| EDDSA Sign (Curve25519) | ⏳           | ⏳      |
| ECDH Decrypt            | ⏳           | ❌      |
| RSA Sign                | ❌           | ✅      |
| RSA Decrypt             | ❌           | ✅      |

## Install

### Prerequisites

#### Consider redundancy

If you lose access to your security key (lost, stolen, broken) **there is no way to recover the keys stored on it**.
For that reason it is highly recommended that you use multiple security keys and/or fallback keyfiles.

#### Install pcsclite

`piv-agent` has transitive dependencies through [`piv-go`](https://github.com/go-piv/piv-go#installation), on [`pcsclite`](https://pcsclite.apdu.fr/).

```
# debian / ubuntu
sudo apt install libpcsclite1
```

### piv-agent

Download the latest [release](https://github.com/smlx/piv-agent/releases), and extract it to a temporary location.
Copy the `piv-agent` binary into your `$PATH`, and the systemd unit files to the correct location:

```
cp deploy/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
```

---
**NOTE**

`ssh-agent` and `gpg-agent` functionality are enabled by default.
Edit the systemd unit files to disable one or the other.

---

## Setup

### Hardware

---
**NOTE**

This procedure is only required once per security key, and wipes any existing keys from PIV slots.

---

By default, `piv-agent` uses three slots on your security key to set up keys with different [touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html): never required, cached (for 15 seconds), and always.

```
# find the name of the security keys (cards)
piv-agent list
# generate new keys
piv-agent setup --pin=123456 --card='Yubico YubiKey FIDO+CCID 01 00' --reset-security-key
# view newly generated keys
piv-agent list
```

### SSH

#### List keys

List your hardware SSH keys:

```
piv-agent list
```

Add the SSH key with the touch policy you want from the list, to any SSH service.
It's a good idea to generate an `ed25519` keyfile and add that to all SSH services too for redundancy.

#### Set `SSH_AUTH_SOCK`

Export the `SSH_AUTH_SOCK` variable in your shell.

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/piv-agent/ssh.socket
```

#### Prefer keys on the security key

By default, `ssh` will offer [keyfiles it finds on disk](https://manpages.debian.org/testing/openssh-client/ssh_config.5.en.html#IdentityFile) _before_ those from the agent.
This is a problem because `piv-agent` is designed to offer keys from the hardware token first, and only fall back to local keyfiles if token keys are refused.
To get `ssh` to ignore local keyfiles and only talk to `piv-agent`, add this line to your `ssh_config`, for all hosts:

```
IdentityFile /dev/null
```

### GPG

#### Import public keys

`gpg` requires public keys to be imported for any private keys stored by the agent, so the `list` command will synthesize a public key based on the private key stored on the hardware.
This public key contains a [User ID packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.11), which must be signed by the private key, so:

* you should provide a name and email which will be embedded in the synthesized public key
* `list --key-formats=gpg` requires a touch of the security key to perform signing on the keys associated with those slots

```
piv-agent list --key-formats=ssh,gpg --pgp-name='Art Vandelay' --pgp-email='art@example.com'
```

Paste these public keys into a `key.asc` file, and run `gpg --import key.asc`.

#### Export fallback keys

---
**NOTE**

This step requires `gpg-agent` to be running, not `piv-agent`.

---

Private keys to be used by `piv-agent` must be exported to `~/.gnupg/piv-agent.secring/`:

```
# set umask for user-only permissions
umask 77
mkdir -p ~/.gnupg/piv-agent.secring
gpg --export-secret-key 0xB346A434C7652C02 > ~/.gnupg/piv-agent.secring/key@example.com.gpg
```

#### Disable gpg-agent

Because `piv-agent` takes over the role of `gpg-agent`, the latter should be disabled:

* Add `no-autostart` to `~/.gnupg/gpg.conf`.
* `systemctl --user disable --now gpg-agent.socket gpg-agent.service; pkill gpg-agent`

## Use

Start the agent sockets, and test:

```
systemctl --user enable --now piv-agent.socket
ssh-add -l
gpg -K
```

#### PIN / Passphrase caching

If your pinentry supports storing credentials I recommend storing the PIN of the security key, but not the passphrase of any fallback keys, as a decent usability/security tradeoff.
This ensures that at least the encrypted key file and its passphrase aren't stored together.
It also has the advantage of ensuring that you don't forget your keyfile passphrase.
But you might forget your PIN, so maybe don't store that either if you're concerned about that possibility? 🤷

#### Add Security Key as a OpenPGP signing subkey

---
**NOTE**

There is currently a [bug](https://dev.gnupg.org/T5555) in GnuPG which doesn't allow ECDSA keys to be added as subkeys correctly.
For now you need to apply the patch described in the bug report to work around this limitation.

---

Adding a `piv-agent` OpenPGP key as a signing subkey of an existing OpenPGP key is a convenient way to integrate a physical Security Key with your existing `gpg` workflow.
This allows you to do things like sign `git` commits using your Yubikey, while keeping the same OpenPGP key ID.
Adding a subkey requires cross-signing, so you need to export the master secret key of your existing OpenPGP key as described above to make it available to `piv-agent`.
There are instructions for adding an existing key as a subkey [here](https://security.stackexchange.com/a/160847).

---
**NOTE**

`gpg` will choose the _newest_ available subkey to perform an action. So it will automatically prefer a newly added `piv-agent` subkey over any existing keyfile subkeys, but fall back to keyfiles if e.g. the Yubikey is not plugged in.

---

## Develop

### Prerequisites

Install build dependencies:

```
# debian/ubuntu
sudo apt install libpcsclite-dev
```

### Build and test

```
make
```

### Build and test manually

This D-Bus variable is required for `pinentry` to use a graphical prompt:

```
go build ./cmd/piv-agent && systemd-socket-activate -l /tmp/piv-agent.sock -E DBUS_SESSION_BUS_ADDRESS ./piv-agent serve --debug
```

Then in another terminal:

```
export SSH_AUTH_SOCK=/tmp/piv-agent.sock
ssh ...
```
