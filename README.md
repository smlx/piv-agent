# PIV Agent

[![Release](https://github.com/smlx/piv-agent/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/piv-agent/actions/workflows/release.yaml)
[![Coverage](https://coveralls.io/repos/github/smlx/piv-agent/badge.svg?branch=main)](https://coveralls.io/github/smlx/piv-agent?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/smlx/piv-agent)](https://goreportcard.com/report/github.com/smlx/piv-agent)
[![User Documentation](https://github.com/smlx/piv-agent/actions/workflows/user-documentation.yaml/badge.svg)](https://smlx.github.io/piv-agent/)

## About

* `piv-agent` is an SSH and GPG agent providing simple integration of [PIV](https://csrc.nist.gov/projects/piv/piv-standards-and-supporting-documentation) hardware (e.g. a [Yubikey](https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html)) with `ssh`, and `gpg` workflows such as [`git`](https://git-scm.com/) signing, [`pass`](https://www.passwordstore.org/) encryption, or [keybase](https://keybase.io/) chat.
* `piv-agent` originated as a reimplementation of [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) because I needed some extra features, and also to gain a better understanding of the PIV applet on security key hardware.
* `piv-agent` makes heavy use of the Go standard library and supplementary `crypto` packages, as well as [`piv-go`](https://github.com/go-piv/piv-go/) and [`pcsclite`](https://pcsclite.apdu.fr/). Thanks for the great software!

---
**DISCLAIMER**

I make no assertion about the security or otherwise of this software and I am not a cryptographer.
If you are, please take a look at the code and send PRs or issues. :green_heart:

---

### Features

* implements (a subset of) both `ssh-agent` and `gpg-agent` functionality
* support for multiple hardware security keys
* support for multiple slots in those keys
* support for multiple touch policies
* all cryptographic keys are generated on the hardware security key, rather than on your laptop
  * secret keys never touch your hard drive
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

Will be tested with (once PIV support [is available](https://github.com/solokeys/solo2/discussions/88)):

* [Solo V2](https://www.kickstarter.com/projects/conorpatrick/solo-v2-safety-net-against-phishing/)

Any device implementing the SCard API (PC/SC), and supported by [`piv-go`](https://github.com/go-piv/piv-go/) / [`pcsclite`](https://pcsclite.apdu.fr/) may work.
If you have tested another device with `piv-agent` successfully, please send a PR adding it to this list.

### Platform support

Currently tested on Linux with `systemd` and macOS with `launchd`.

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
| ECDH Decrypt            | ✅           | ✅      |
| RSA Sign                | ❌           | ✅      |
| RSA Decrypt             | ❌           | ✅      |

## Install and Use

Please see the [documentation](https://smlx.github.io/piv-agent/).

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

### Build and test the documentation

```
cd docs && make serve
```
