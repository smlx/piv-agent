---
title: "Use"
weight: 30
description: Use piv-agent with ssh and gpg.
---

## Start `piv-agent.socket`

Start the agent sockets, and test:

```
systemctl --user enable --now piv-agent.socket
ssh-add -l
gpg -K
```

This should be enough to allow you to use `piv-agent`.

## Common operations

### List keys

```
piv-agent list
```

If this command returns an empty list, it may be because the running agent is holding a transaction to the hardware security device.
The solution is to stop the agent and run the list command again.

```
systemctl --user stop piv-agent
# should work now..
piv-agent list
```

## Advanced

This section describes some ways to enhance the usability of `piv-agent`.

### PIN / Passphrase caching

If your pinentry supports caching credentials, `piv-agent` will offer to cache the PIN of the hardware security device.
It will not cache the passphrase of any fallback keys.

This is a usability/security tradeoff that ensures that at least the encrypted private key file and its passphrase aren't stored together on disk.
It also has the advantage of ensuring that you don't forget your keyfile passphrase, as you'll need to enter it periodically.

However you might also forget your device PIN, so maybe don't cache that either if you're concerned about that possibility.
