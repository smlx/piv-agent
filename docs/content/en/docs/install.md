---
title: "Install"
weight: 10
---

## Prerequisites

### Consider redundancy

If you lose access to your hardware security device (for example if it is lost, stolen, or broken) **there is no way to recover the keys stored on it**.
For that reason it is highly recommended that you use fallback SSH or GPG keyfiles and/or multiple hardware security devices.

### Install pcsclite

`piv-agent` has transitive dependencies through [`piv-go`](https://github.com/go-piv/piv-go#installation), on [`pcsclite`](https://pcsclite.apdu.fr/).

```
# debian / ubuntu
sudo apt install libpcsclite1
# TODO: other platforms
...
```

## Install piv-agent

Download the latest [release](https://github.com/smlx/piv-agent/releases), and extract it to a temporary location.

### Linux

Copy the `piv-agent` binary into your `$PATH`, and the `systemd` unit files to the correct location:

```
sudo cp piv-agent /usr/local/bin/
cp deploy/systemd/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
```

### macOS

`piv-agent` requires [Homebrew](https://brew.sh) in order to install dependencies.
So install that first.

Copy the `piv-agent` binary into your `$PATH`, and the `launchd` `.plist` files to the correct location:

```
sudo cp piv-agent /usr/local/bin/
cp deploy/launchd/com.github.smlx.piv-agent.plist ~/Library/LaunchAgents/
```

From what I can tell `.plist` files only support absolute file paths, even for user agents.
So edit `~/Library/LaunchAgents/com.github.smlx.piv-agent.plist` and update the path to `$HOME/.gnupg/S.gpg-agent`.

If you plan to use `gpg`, install it via `brew install gnupg`.
If not, you still need a `pinentry`, so `brew install pinentry`.

If `~/.gnupg` doesn't already exist, create it.

```
mkdir ~/.gnupg
chmod 700 ~/.gnupg
```

Then enable the service:

```
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.github.smlx.piv-agent.plist
launchctl enable gui/$UID/com.github.smlx.piv-agent
```

A socket should appear in `~/.gnupg/S.gpg-agent`.

Disable `ssh-agent` to avoid `SSH_AUTH_SOCK` environment variable conflict.

```
launchctl disable gui/$UID/com.openssh.ssh-agent
```

Set `launchd` user path to include `/usr/local/bin/` for `pinentry`.

```
sudo launchctl config user path $PATH
```

Reboot and log back in.

### Socket activation

`piv-agent` relies on [socket activation](https://0pointer.de/blog/projects/socket-activated-containers.html), and is currently tested with `systemd` on Linux, and `launchd` on macOS.
It doesn't listen to any sockets directly, and instead requires the init system to pass file descriptors to the `piv-agent` process after it is running.
This requirement makes it possible to exit the process when not in use.

`ssh-agent` and `gpg-agent` functionality are enabled by default in the `systemd` and `launchd` configuration files.

On Linux, the index of the sockets listed in `piv-agent.socket` are indicated by the arguments to `--agent-types`.
