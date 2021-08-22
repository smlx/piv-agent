---
title: "Documentation"
linkTitle: "Documentation"
weight: 20
menu:
  main:
    weight: 20
---

## Install

### Prerequisites

#### Consider redundancy

If you lose access to your security key (lost, stolen, broken) **there is no way to recover the keys stored on it**.
For that reason it is highly recommended that you use fallback SSH or GPG keyfiles and/or multiple hardware security keys.

#### Install pcsclite

`piv-agent` has transitive dependencies through [`piv-go`](https://github.com/go-piv/piv-go#installation), on [`pcsclite`](https://pcsclite.apdu.fr/).

```
# debian / ubuntu
sudo apt install libpcsclite1
```

### Install piv-agent

Download the latest [release](https://github.com/smlx/piv-agent/releases), and extract it to a temporary location.
Copy the `piv-agent` binary into your `$PATH`, and the systemd unit files to the correct location:

```
sudo cp piv-agent /usr/local/bin/
cp deploy/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
```

#### Socket activation

`piv-agent` relies on [socket activation](https://0pointer.de/blog/projects/socket-activated-containers.html), and is currently only tested with `systemd`.
It doesn't listen to any sockets directly, and instead requires the init system to pass file descriptors to the process after it is running.
This requirement makes it possible to exit the process when not in use.

`ssh-agent` and `gpg-agent` functionality are enabled by default in `piv-agent.service` and `piv-agent.socket`.
The index of the sockets listed in `piv-agent.socket` are indicated by the arguments to `--agent-types`.

## Setup

### Hardware

---
**WARNING**

This procedure resets the state of the PIV device and wipes any existing keys from PIV slots.

---

This procedure is only required once per hardware security device.
Performing it a second time will change the keys on the device.

By default, `piv-agent` uses three slots on your security key to set up keys with different [touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html): never required, cached (for 15 seconds), and always.

```
# find the name of the security keys (cards)
piv-agent list
# generate new keys
piv-agent setup --pin=123456 --card='Yubico YubiKey FIDO+CCID 01 00' --reset-security-key
# view newly generated keys (SSH only by default)
piv-agent list
```

### SSH

#### List keys

List your hardware SSH keys:

```
piv-agent list
```

Add the public SSH key with the touch policy you want from the list, to any SSH service.

#### Set `SSH_AUTH_SOCK`

Export the `SSH_AUTH_SOCK` variable in your shell.

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/piv-agent/ssh.socket
```

#### Prefer keys on the hardware security device

It's a good idea to generate an `ed25519` keyfile and add that to all SSH services too for redundancy.
`piv-agent` will fall back to `~/.ssh/id_ed25519` automatically.

By default, `ssh` will offer [keyfiles it finds on disk](https://manpages.debian.org/testing/openssh-client/ssh_config.5.en.html#IdentityFile) _before_ those from the agent.
This is a problem because `piv-agent` is designed to offer keys from the hardware token first, and only fall back to local keyfiles if token keys are refused.
To get `ssh` to ignore local keyfiles and only talk to `piv-agent`, add this line to your `ssh_config`, for all hosts:

```
IdentityFile /dev/null
```

### GPG

#### Import public keys

`gpg` requires public keys to be imported for any private keys stored by the agent.
This structure of a GPG public key contains a [User ID packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.11), which must be signed by the associated _private key_.

The `piv-agent list` command can synthesize a public key for the private key stored on the security hardware device.
Listing a GPG key via `piv-agent list --key-formats=gpg` will require a touch of the security key to perform signing on the keys associated with those slots (due to the User ID packet).
You should provide a name and email which will be embedded in the synthesized public key (see `piv-agent --help list`).

```
piv-agent list --key-formats=ssh,gpg --pgp-name='Art Vandelay' --pgp-email='art@example.com'
```

Paste these public keys into a `key.asc` file, and run `gpg --import key.asc`.

#### Export fallback keys

Private GPG keys to be used by `piv-agent` must be exported to the directory`~/.gnupg/piv-agent.secring/`.

---
**NOTE**

This step requires `gpg-agent` to be running, not `piv-agent`.

---

```
# set umask for user-only permissions
umask 77
mkdir -p ~/.gnupg/piv-agent.secring
gpg --export-secret-key 0xB346A434C7652C02 > ~/.gnupg/piv-agent.secring/art@example.com.gpg
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

If your pinentry supports storing credentials you can the PIN of the security key, but not the passphrase of any fallback keys, as a usability/security tradeoff.
This ensures that at least the encrypted key file and its passphrase aren't stored together.
It also has the advantage of ensuring that you don't forget your keyfile passphrase.
But you might forget your PIN, so maybe don't store that either if you're concerned about that possibility? 🤷

#### Add Security Key as a OpenPGP signing subkey

---
**NOTE**

There is a [bug](https://dev.gnupg.org/T5555) in certain versions of GnuPG which doesn't allow ECDSA keys to be added as subkeys correctly.
You'll need a verion of GnuPG where that bug is fixed for this procedure to work.

---

Adding a `piv-agent` OpenPGP key as a signing subkey of an existing OpenPGP key is a convenient way to integrate a physical Security Key with your existing `gpg` workflow.
This allows you to do things like sign `git` commits using your Yubikey, while keeping the same OpenPGP key ID.
Adding a subkey requires cross-signing, so you need to export the master secret key of your existing OpenPGP key as described above to make it available to `piv-agent`.
There are instructions for adding an existing key as a subkey [here](https://security.stackexchange.com/a/160847).

`gpg` will choose the _newest_ available subkey to perform an action. So it will automatically prefer a newly added `piv-agent` subkey over any existing keyfile subkeys, but fall back to keyfiles if e.g. the Yubikey is not plugged in.
