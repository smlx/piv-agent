---
title: "FAQ"
weight: 40
---

## How do I switch between gpg-agent and piv-agent

### Linux (systemd)

Stop both `gpg-agent` and `piv-agent`:

{{% alert title="Note" %}}
The `pkill` is required because `gpg` may be configured to automatically start `gpg-agent` in a manner which is not managed by `systemd`.
{{% /alert %}}

```
systemctl --user stop gpg-agent.socket gpg-agent.service piv-agent.socket piv-agent.service; pkill gpg-agent
```

Start `piv-agent` sockets:

```
systemctl --user start piv-agent.socket
```

Or start `gpg-agent` socket:

```
systemctl --user start gpg-agent.socket
```

### macOS (launchd)

Stop `piv-agent`:

```
launchctl disable gui/$UID/com.github.smlx.piv-agent
```

Start `piv-agent` sockets:

```
launchctl enable gui/$UID/com.github.smlx.piv-agent
```
