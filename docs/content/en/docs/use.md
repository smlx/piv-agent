---
title: "Use"
weight: 30
description: Use piv-agent with ssh and age.
---

## Start `piv-agent.socket`

Start the agent sockets, and test:

```
systemctl --user enable --now piv-agent.socket
ssh-add -l
```

This should be enough to allow you to use `piv-agent`.

## Common operations

### List keys

```
piv-agent status
```

If this command returns an empty list, it may be because the running agent is holding a transaction to the hardware security device.
The solution is to stop the agent and run the list command again.

```
systemctl --user stop piv-agent
# should work now..
piv-agent status
```

### Encrypting and Decrypting with age

You can list your age identities and their associated recipients by using the `status` command:

```bash
piv-agent status --age-identities
```

This will print the identity details for each initialized decrypting key on your security token.
The output format includes the hardware identity metadata followed by the identity string, which looks like this:

```
# Hardware Identity for YubiKey 5 serial 12345678 slot 82
# Host name: hostname
# Seed file: 0123456789abcdef
# Recipient: age1...
AGE-PLUGIN-PIV-AGENT-1...
```

To encrypt a file for your hardware identity, use the identity file generated during setup to derive the recipient string, or provide the recipient string directly:

```bash
# Encrypt a file to your hardware token
age -R ~/.config/age/identities.txt -o secret.txt.age secret.txt
```

To decrypt the file, provide the same identities file.
The `age` client will automatically communicate with the hardware token via the plugin:

```bash
# Decrypt the file
age -d -i ~/.config/age/identities.txt secret.txt.age
```

## Advanced

This section describes some ways to enhance the usability of `piv-agent`.

### PIN / Passphrase caching

If your pinentry supports caching credentials, `piv-agent` will offer to cache the PIN of the hardware security device.
It will not cache the passphrase of any fallback keys.

This is a usability/security tradeoff that ensures that at least the encrypted private key file and its passphrase aren't stored together on disk.
It also has the advantage of ensuring that you don't forget your keyfile passphrase, as you'll need to enter it periodically.

However you might also forget your device PIN, so maybe don't cache that either if you're concerned about that possibility.

### Wait for device before Git signing

If you use a hardware security key for Git commit signing, you can configure Git to wait for the device to be plugged in before falling back to a software key.
This is especially useful if `piv-agent` is managing both hardware and software SSH keys.

You can create a script `~/.config/git/defaultKey.sh` that uses the `piv-agent wait-for-device` command to notify the user to plug in a device and wait for the device before returning.
The user can immediately fall back to the keyfile by dismissing the notification.

```bash
#!/bin/sh
# Wait up to 60 seconds for a hardware device to be plugged in.
piv-agent wait-for-device

# Print the hardware key if available, otherwise fall back to keyfile.
# Filter the hardware keys by serial number and touch policy.
key=$(ssh-add -L | awk '/#(123456|123457), touch policy: never/ { print "key::" $0 }')
if [ "$key" ]; then
	echo "$key"
	exit
fi
ssh-add -L | awk '/id_ed25519/ { print "key::" $0 }'
```

Configure Git to use this script:

```bash
chmod +x ~/.config/git/defaultKey.sh
git config --global gpg.ssh.defaultKeyCommand "~/.config/git/defaultKey.sh"
```

