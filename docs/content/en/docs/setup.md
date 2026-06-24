---
title: "Setup"
weight: 20
description: Set up piv-agent to work with your hardware.
---

## Hardware

### Default setup

> [!WARNING]
> This procedure resets the state of the PIV applet to factory defaults and wipes any existing keys from _all_ PIV slots.

This procedure is only required once per hardware security device.
Performing it a second time will reset the keys on the PIV applet of the device.
It will not make any changes to applets providing other functionality the device may have, such as WebAuthn.

By default, `piv-agent` uses up to six slots on your hardware security device to set up three signing keys, and up to three decrypting keys.
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
| `0x82`  | Key Management (retired) | Decrypting        | Always       |
| `0x83`  | Key Management (retired) | Decrypting        | Always *     |
| `0x84`  | Key Management (retired) | Decrypting        | Always *     |

\* Used when configuring the security key for decrypting on multiple machines.

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

> [!WARNING]
> `piv-agent` has been designed to work best with the default setup.
> Only set up single slots if you know what you are doing.
>
> This action can be destructive.
> If you reset a slot which already contains a key, that key will be lost.

It is possible to set up a single PIV slot on your hardware device without resetting the PIV applet entirely.
This means that you can target a single slot to set up a key if the slot has not been set up yet, or reset a key if the slot already contains one.
Other PIV slots will not be affected, and will retain their existing keys.

For example this command will reset just the decrypting key with touch policy `never` on your Yubikey:

```bash
piv-agent setup --serial=12345678 --pin=123456 --overwrite-slot=82 --touch-policy=never
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

## Age

### Setup

To set up `age` with your hardware security device, the default `piv-agent setup` command will generate a local seed and assign it to the next available decrypting slot (typically `0x82`).

To view your age identities, use the `status` command:

```bash
piv-agent status --age-identities
```

Save the output identity to a file (for example, `~/.config/age/identities.txt`) so you can use it to encrypt or decrypt files with `age`.

> [!WARNING]
> Running the `piv-agent setup --add-decrypting-key` command a second time will provision a new slot on the device with a new seed.
> The old seeds will remain in the credential store so existing files can still be decrypted, and the old slot can still be used if needed.

### Offline Recovery Identity (Break-Glass)

Generating an offline recovery identity (`mlkem768x25519` native post-quantum key) alongside your hardware-bound identity is highly recommended.
This provides a "break-glass" mechanism for two important scenarios:

* **Disaster Recovery (Lost Hardware):** If your machine is destroyed or your hardware token is lost, the local TPM-sealed seed is permanently inaccessible.
  Having the offline seed allows you to decrypt your data on any machine using a standard `age` client.
* **High-Volume Batch Decryption:** If your hardware token is configured with an `always` touch policy, batch decrypting many files (e.g., during a password manager migration) would require hundreds of physical touches.
  You can temporarily use the software offline key to perform batch decryption instantly using CPU power alone.

To generate this recovery key, use the standard `age-keygen` tool:

```bash
# Generate a native post-quantum identity (X-Wing)
age-keygen -pq -o /tmp/recovery-identity.txt
```

You should print the resulting `AGE-SECRET-KEY-PQ-...` string as a QR code and store it entirely offline in cold storage.
You can generate a QR code using `qrencode`:

```bash
# Install qrencode if necessary. Example command for Debian/Ubuntu.
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

> [!NOTE]
> Passage doesn't currently support multiple identities. There's a PR for this [here](https://github.com/FiloSottile/passage/pull/71).

```bash
piv-agent status --age-identities --decrypting-slots=82 >> $HOME/.passage/identities
```

Configure the passage recipients.
These will be used by passage for encryption.

```bash
piv-agent status --age-recipients --decrypting-slots=82 >> $HOME/.passage/store/.age-recipients
```

Now you can migrate from pass to passage.

`pass2passage.sh` will extract all your `pass` keys and insert them into your `passage` store.

```bash
./contrib/pass2passage.sh
```

Now you can use `passage` instead of `pass`.

If you are a `fzf` user, try the fuzzy-find script described in the `passage` README!
