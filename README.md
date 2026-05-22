# PIV Agent

[![Release](https://github.com/smlx/piv-agent/actions/workflows/release.yaml/badge.svg)](https://github.com/smlx/piv-agent/actions/workflows/release.yaml)
[![coverage](https://raw.githubusercontent.com/smlx/piv-agent/badges/.badges/main/coverage.svg)](https://github.com/smlx/piv-agent/actions/workflows/coverage.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/smlx/piv-agent)](https://goreportcard.com/report/github.com/smlx/piv-agent)
[![User Documentation](https://github.com/smlx/piv-agent/actions/workflows/user-documentation.yaml/badge.svg)](https://smlx.github.io/piv-agent/)

---
⚠️🚧 **BREAKING CHANGES** 🚧⚠️

`piv-agent` is currently going through a heavy refactor: I am removing GnuPG support.

This is for several reasons, including:

* It is terribly complex, and its agent protocol moreso. The agent protocol is also poorly documented.
* Supporting it requires maintenance and several additional dependencies, including one that I had to fork.
* It has well-documented [technical](https://lwn.net/Articles/1054220/) [problems](https://soatok.blog/2024/11/15/what-to-use-instead-of-pgp/#:~:text=Encrypting%20Files).
* I don't use it anymore.

To that end, I am planning the following release schedule for `piv-agent`:

1. ✅ `v1.x` will be released. It will support `age` via a plugin, in addition to SSH and GPG.
1. ⏳ `v1.x` will be maintained for a short period (6 months). This is so that anyone else using `piv-agent` has a chance to migrate away from GPG, or find another solution.
1. ⏳ `v2.x` will be released shortly after `v1.x`, with GPG support totally removed. Active development will only occur on `v2.x`.

Please test if you can, but be aware there may be breakage. In particular, the age plugin support is experimental: until this warning is removed, the identity format is unstable.

Discussion of this plan and updates happens [here](https://github.com/smlx/piv-agent/discussions/273).

---

## About

* `piv-agent` is an SSH and [age](https://github.com/FiloSottile/age) plugin agent providing simple integration of [PIV](https://csrc.nist.gov/projects/piv/piv-standards-and-supporting-documentation) hardware (e.g. a [Yubikey](https://developers.yubico.com/yubico-piv-tool/YubiKey_PIV_introduction.html)) with `ssh`, and `age` workflows such as [`git`](https://git-scm.com/) signing and [`passage`](https://github.com/FiloSottile/passage) password storage.
* `piv-agent` originated as a reimplementation of [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) because I needed some extra features, and also to gain a better understanding of the PIV applet on security key hardware.
* `piv-agent` makes heavy use of the Go standard library and supplementary `crypto` packages, as well as [`piv-go`](https://github.com/go-piv/piv-go/) and [`pcsclite`](https://pcsclite.apdu.fr/). Thanks for the great software!

---
**DISCLAIMER**

I make no assertion about the security or otherwise of this software and I am not a cryptographer.
If you are, please take a look at the code and send PRs or issues. :green_heart:

---

### Platform support

`piv-agent` has a hard dependency on Linux and systemd.
At this time no other OS stack is supported.

### Features

* implements (a subset of) both `ssh-agent` and `gpg-agent` functionality
* implements an [age plugin](https://github.com/C2SP/C2SP/blob/main/age-plugin.md): age-plugin-piv-agent
* support for multiple hardware security keys
* support for multiple slots in those keys
* support for multiple touch policies
* all cryptographic keys are generated on the hardware security key, rather than on your laptop
  * secret keys never touch your hard drive
* uses systemd socket activation
  * as a result, automatically drop the transaction on the security key and cached passphrases after some period of disuse
* provides "fall-back" to traditional SSH and OpenPGP keyfiles

### Design philosophy

This agent should require no interaction and in general do the right thing when security keys are plugged/unplugged, laptop is power cycled, etc.

It is highly opinionated:

* Only supports 256-bit ECC keys (P-256) on hardware tokens
* Only supports ed25519 SSH keys on disk (`~/.ssh/id_ed25519`)
* Only supports the [mlkem768p256tag](https://github.com/C2SP/C2SP/blob/main/age.md#mlkem768p256tag-recipient-stanza) identity/recipient type
* Requires socket activation

It makes some concession to practicality with OpenPGP:

* Supports RSA signing and decryption for OpenPGP keyfiles.
  RSA OpenPGP keys are widespread and Debian in particular [only documents RSA keys](https://wiki.debian.org/Keysigning).

It tries to strike a balance between security and usability:

* Takes a persistent transaction on the hardware token, effectively caching the PIN.
* Caches passphrases for on-disk keys (i.e. `~/.ssh/id_ed25519`) in memory, so these only need to be provided once after the agent starts.
* After a period of inactivity it exits, dropping both the transaction and the passphrase.
  Socket activation restarts it automatically as required.

### Hardware support

Tested with:

* [YubiKey 5C](https://www.yubico.com/au/product/yubikey-5c/), firmware versions 5.2.4, 5.7.1.

If you have tested another device or firmware version with `piv-agent` successfully, please send a PR adding it to this list.

### Protocol / Encryption Algorithm support

| Supported | Not Supported | Support Blocked (Curve25519) |
| ---       | ---           | ---                          |
| ✅        | ❌            | ⏳                           |

#### ssh-agent

|                     | Security Key | Keyfile |
| ---                 | ---          | ---     |
| ecdsa-sha2-nistp256 | ✅           | ❌      |
| ssh-ed25519         | ❌           | ✅      |


#### gpg-agent

|                               | Security Key | Keyfile |
| ---                           | ---          | ---     |
| ECDSA Sign (NIST Curve P-256) | ✅           | ✅      |
| ECDH Decrypt                  | ✅           | ✅      |
| RSA Sign                      | ❌           | ✅      |
| RSA Decrypt                   | ❌           | ✅      |

#### age

`piv-agent`, and its age plugin `age-plugin-piv-agent` only support the `mlkem768p256tag` identity/recipient type.

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
