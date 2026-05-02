---
title: "Setup"
weight: 20
description: Set up piv-agent to work with your hardware.
---

## Hardware

### Default setup

{{% alert title="Warning" color="warning" %}}
This procedure resets the state of the PIV applet to factory defaults and wipes any existing keys from _all_ PIV slots.
{{% /alert %}}

This procedure is only required once per hardware security device.
Performing it a second time will reset the keys on the PIV applet of the device.
It will not make any changes to applets providing other functionality the device may have, such as WebAuthn.

By default, `piv-agent` uses six slots on your hardware security device to set up three signing keys, and three decrypting key.
Each of the signing and decrypting keys have different [touch policies](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html): never required, cached (for 15 seconds), and always.

The three signing keys are used for SSH signing.
The decrypting keys are used for age decryption.
Having a range of touch policies available facilitates practical use of the hardware security device.

The default slot usage by `piv-agent` is detailed in the table below, with reference to the [Yubikey certificate slot usage description](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html).
It is highly recommended to use these setup defaults as this has had the most usability testing.

| Slot ID | Nominal purpose          | `piv-agent` usage | Touch policy |
| ---     | ---                      | ---               | ---          |
| `0x9a`  | PIV Authentication       | Signing           | Cached       |
| `0x9c`  | Digital Signature        | Signing           | Always       |
| `0x9e`  | Card Authentication      | Signing           | Never        |
| `0x9d`  | Key Management           | Decrypting        | Cached       |
| `0x82`  | Key Management (retired) | Decrypting        | Always       |
| `0x83`  | Key Management (retired) | Decrypting        | Never        |

#### Example setup workflow

```bash
# find the serial numbers of the hardware security devices
piv-agent status

# generate new keys (PIN will be requested via interactive prompt)
piv-agent setup --serial=12345678

# view newly generated keys (SSH only by default)
piv-agent status
```

### Single slot setup

{{% alert title="Warning" color="warning" %}}
`piv-agent` has been designed to work best with the default setup.
Only set up single slots if you know what you are doing.

This action can be destructive.
If you reset a slot which already contains a key, that key will be lost.
{{% /alert %}}

It is possible to set up a single PIV slot on your hardware device without resetting the PIV applet entirely.
This means that you can target a single slot to set up a key if the slot has not been set up yet, or reset a key if the slot already contains one.
Other PIV slots will not be affected, and will retain their existing keys.

For example this command will reset just the decrypting key with touch policy `never` on your Yubikey:

```bash
piv-agent setup --serial=12345678 --pin=123456 --decrypting-keys=never
```

See the interactive help for more usage details:

```bash
piv-agent setup --help
```

## SSH

### List keys

List your hardware SSH keys:

```bash
piv-agent status
```

Add the public SSH key with the touch policy you want from the list, to any SSH service.

### Set `SSH_AUTH_SOCK`

Export the `SSH_AUTH_SOCK` variable in your shell.

```bash
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/piv-agent/ssh.socket
```

### List keys using ssh-add

Confirm that `ssh-add` can talk to `piv-agent` by listing the keys available.

```bash
ssh-add -L
```

You should see the Yubikey ssh keys listed.

### Prefer keys on the hardware security device

If you don't already have one, it's a good idea to generate an `ed25519` keyfile and add that to all SSH services too for redundancy.
`piv-agent` will automatically load and use `~/.ssh/id_ed25519` as a fallback.

By default, `ssh` will offer [keyfiles it finds on disk](https://manpages.debian.org/testing/openssh-client/ssh_config.5.en.html#IdentityFile) _before_ those from the agent.
This is a problem because `piv-agent` is designed to offer keys from the hardware token first, and only fall back to local keyfiles if token keys are refused.

To get `ssh` to offer hardware keys first instead, copy the output of the hardware keys you want to offer from the `ssh-add -L` command to a local file:

```bash
# list keys
ssh-add -L
# add output to local file
ssh-add -L | grep cached > ~/.ssh/id_yk_cached.pub
```

And add a line referencing the file to your `ssh_config`.

```
IdentityFile ~/.ssh/id_yk_cached.pub
```

## GPG

### Export fallback cryptographic keys

Private GPG keys to be used by `piv-agent` must be exported to the directory `~/.gnupg/piv-agent.secring/`.

{{% alert title="Note" %}}
This step requires `gpg-agent` to be running, not `piv-agent`.
See the [FAQ](../../docs/faq) for how to switch between the two services.
{{% /alert %}}

{{% alert title="Note" %}}
If your private key is encrypted using a password (it should be!), the encryption is retained during export.
The key is still stored encrypted in the exported keyfile - it's just converted into a standard OpenPGP format that `piv-agent` can read.
{{% /alert %}}

```bash
# example
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

### Import public cryptographic keys from the security hardware

Before any private GPG keys on the hardware dvice can be used, `gpg` requires their public keys to be imported.
This structure of a GPG public key contains a [User ID packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.11), which must be signed by the associated _private key_.

The `piv-agent status` command can be used to view the status of the keys on the device.
Listing the status via `piv-agent status` will show the keys associated with those slots.

```bash
# example
piv-agent status
```

Paste the public key(s) you would like to use into a `key.asc` file, and run `gpg --import key.asc`.

## GPG Advanced

If you have followed the setup instructions to this point you should have a functional `gpg-agent` backed by a PIV hardware device.
The following instructions allow deeper integration of the hardware with existing GPG keys and workflows.

### Add cryptographic key stored in hardware as a GPG signing subkey

{{% alert title="Note" %}}
There is a [bug](https://dev.gnupg.org/T5555) in current versions of GnuPG which doesn't allow ECDSA keys to be added as signing subkeys.
This is unfortunate since signing is much more useful than decryption.

Until this is fixed upstream, [here is a Docker image](https://github.com/smlx/gnupg-piv-agent) containing a patched version of `gpg` which will add ECDSA keys as signing subkeys.
{{% /alert %}}

Adding a `piv-agent` OpenPGP key as a signing subkey of an existing OpenPGP key is a convenient way to integrate a hardware security device with your existing `gpg` workflow.
This allows you to do things like sign `git` commits using your Yubikey, while keeping the same OpenPGP key ID.
Adding a subkey requires cross-signing between the master key and sub key, so you need to export the master secret key of your existing OpenPGP key as described above to make it available to `piv-agent`.

`gpg` will choose the _newest_ available subkey to perform an action. So it will automatically prefer a newly added `piv-agent` subkey over any existing keyfile subkeys, but fall back to keyfiles if e.g. the Yubikey is not plugged in.

See the [GPG Walkthrough](../../docs/gpg-walkthrough) for an example of this procedure.

## Age

### Setup

To set up `age` with your hardware security device, use the `generate-seeds` command to create your seeds and output your corresponding hardware identity:

```bash
age-plugin-piv-agent generate-seeds
```

Save the output identity to a file (for example, `~/.config/age/identities.txt`) so you can use it to encrypt or decrypt files with `age`.

{{% alert title="Warning" color="warning" %}}
Running the `generate-seeds` command a second time will generate new random seeds and new identities. The old seeds will remain in the credential store so existing files can still be decrypted, but you will receive different identity strings.
{{% /alert %}}

### Offline Recovery Identity (Break-Glass)

Generating an offline recovery identity (`mlkem768x25519` native post-quantum key) alongside your hardware-bound identity is highly recommended. This provides a "break-glass" mechanism for two important scenarios:

* **Disaster Recovery (Lost Hardware):** If your machine is destroyed or your hardware token is lost, the local TPM-sealed seed is permanently inaccessible. Having the offline seed allows you to decrypt your data on any machine using a standard `age` client.
* **High-Volume Batch Decryption:** If your hardware token is configured with an `always` touch policy, batch decrypting many files (e.g., during a password manager migration) would require hundreds of physical touches. You can temporarily use the software offline key to perform batch decryption instantly using CPU power alone.

To generate this recovery key, use the standard `age-keygen` tool:

```bash
# Generate a native post-quantum identity (X-Wing)
age-keygen -pq -o /tmp/recovery-identity.txt
```

You should print the resulting `AGE-SECRET-KEY-PQ-...` string as a QR code and store it entirely offline in cold storage. On Debian Linux, you can easily generate a QR code using `qrencode`:

```bash
# Install qrencode if necessary
sudo apt-get install qrencode

# Generate the QR code image
qrencode -o /tmp/recovery-qr.png -s 6 < <(grep -v ^# /tmp/recovery-identity.txt)

# Or display it directly in the terminal
qrencode -t ANSI256 < <(grep -v ^# /tmp/recovery-identity.txt)
```

When encrypting files, specify **both** your hardware-backed public key and your offline recovery public key as recipients to ensure you can always recover your data.

### Passage migration walkthrough

Once you have complete the setup and offline recovery sections above, this section documents how you can migrate from [pass](https://www.passwordstore.org/) to [passage](https://github.com/FiloSottile/passage) using `piv-agent`.

Set up the storage:

```bash
mkdir -p .passage/store
chmod -R 0750 .passage
```

Configure the passage identities.
These will be used by passage for decryption.

{{% alert title="Note" color="note" %}}
Passage doesn't currently support multiple identities. There's a PR for this [here](https://github.com/FiloSottile/passage/pull/71).
{{% /alert %}}

```bash
piv-agent status --age-identities --decrypting-keys=always >> $HOME/.passage/identities
```

Configure the passage recipients.
These will be used by passage for encryption.

```bash
piv-agent status --age-recipients --decrypting-keys=always >> $HOME/.passage/store/.age-recipients
```

Now you can migrate from pass to passage.

`pass2passage.sh` will extract all your `pass` keys and insert them into your `passage` store.

```bash
./contrib/pass2passage.sh
```

Now you can use `passage` instead of `pass`.

If you are a `fzf` user, try the fuzzy-find script described in the `passage` README!
