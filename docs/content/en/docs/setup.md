---
title: "Setup"
weight: 20
---

## Hardware

---
**WARNING**

This procedure resets the state of the PIV applet and wipes any existing keys from PIV slots.

---

This procedure is only required once per hardware security device.
Performing it a second time will reset the keys on the PIV applet of the device.
It will not make any changes to other functionality the device may have, such as WebAuthn.

By default, `piv-agent` uses three slots on your hardware security device to set up keys with different [touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html): never required, cached (for 15 seconds), and always.

```
# find the name of the hardware security devices (cards)
piv-agent list
# generate new keys
piv-agent setup --pin=123456 --card='Yubico YubiKey FIDO+CCID 01 00' --reset-security-key
# view newly generated keys (SSH only by default)
piv-agent list
```

## SSH

### List keys

List your hardware SSH keys:

```
piv-agent list
```

Add the public SSH key with the touch policy you want from the list, to any SSH service.

### Set `SSH_AUTH_SOCK`

Export the `SSH_AUTH_SOCK` variable in your shell.

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/piv-agent/ssh.socket
```

### Prefer keys on the hardware security device

If you don't already have one, it's a good idea to generate an `ed25519` keyfile and add that to all SSH services too for redundancy.
`piv-agent` will automatically load and use `~/.ssh/id_ed25519` as a fallback.

By default, `ssh` will offer [keyfiles it finds on disk](https://manpages.debian.org/testing/openssh-client/ssh_config.5.en.html#IdentityFile) _before_ those from the agent.
This is a problem because `piv-agent` is designed to offer keys from the hardware token first, and only fall back to local keyfiles if token keys are refused.
To get `ssh` to ignore local keyfiles and only talk to `piv-agent`, add this line to your `ssh_config`, for all hosts:

```
IdentityFile /dev/null
```

## GPG

### Import public keys

`gpg` requires public keys to be imported for any private keys stored by the agent.
This structure of a GPG public key contains a [User ID packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.11), which must be signed by the associated _private key_.

The `piv-agent list` command can synthesize a public key for the private key stored on the security hardware device.
Listing a GPG key via `piv-agent list --key-formats=gpg` will require a touch to perform signing on the keys associated with those slots (due to the User ID packet).
You should provide a name and email which will be embedded in the synthesized public key (see `piv-agent --help list`).

```
piv-agent list --key-formats=ssh,gpg --pgp-name='Art Vandelay' --pgp-email='art@example.com'
```

Paste these public keys into a `key.asc` file, and run `gpg --import key.asc`.

### Export fallback keys

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

### Disable gpg-agent

It is not possible to set a custom path for the `gpg-agent` socket in a similar manner to `ssh-agent`.
Instead `gpg-agent` always uses a hard-coded path for its socket.
In order for `piv-agent` to work with `gpg`, it sets up a socket in this same default location.
To avoid conflict over this path, `gpg-agent` should be disabled.

This is how you can disable `gpg-agent` on Debian/Ubuntu:

* Add `no-autostart` to `~/.gnupg/gpg.conf`.
* `systemctl --user disable --now gpg-agent.socket gpg-agent.service; pkill gpg-agent`

Other platforms may have slightly different instructions - PRs welcome.
