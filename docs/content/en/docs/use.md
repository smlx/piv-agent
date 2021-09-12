---
title: "Use"
weight: 30
---

## Start `piv-agent.socket`

Start the agent sockets, and test:

```
systemctl --user enable --now piv-agent.socket
ssh-add -l
gpg -K
```

This should be enough to allow you to use `piv-agent`.

## Advanced

This section describes some ways to enhance the usability of `piv-agent`.

### PIN / Passphrase caching

If your pinentry supports caching credentials, `piv-agent` will offer to cache the PIN of the hardware security device.
It will not cache the passphrase of any fallback keys.

This is a usability/security tradeoff that ensures that at least the encrypted private key file and its passphrase aren't stored together on disk.
It also has the advantage of ensuring that you don't forget your keyfile passphrase, as you'll need to enter it periodically.

However you might also forget your device PIN, so maybe don't cache that either if you're concerned about that possibility.

### Add hardware key as a OpenPGP signing subkey

---
**NOTE**

There is a [bug](https://dev.gnupg.org/T5555) in certain versions of GnuPG which doesn't allow ECDSA keys to be added as subkeys correctly.
You'll need a verion of GnuPG where that bug is fixed for this procedure to work.

---

Adding a `piv-agent` OpenPGP key as a signing subkey of an existing OpenPGP key is a convenient way to integrate a hardware security device with your existing `gpg` workflow.
This allows you to do things like sign `git` commits using your Yubikey, while keeping the same OpenPGP key ID.
Adding a subkey requires cross-signing, so you need to export the master secret key of your existing OpenPGP key as described above to make it available to `piv-agent`.
There are instructions for adding an existing key as a subkey [here](https://security.stackexchange.com/a/160847).

`gpg` will choose the _newest_ available subkey to perform an action. So it will automatically prefer a newly added `piv-agent` subkey over any existing keyfile subkeys, but fall back to keyfiles if e.g. the Yubikey is not plugged in.
