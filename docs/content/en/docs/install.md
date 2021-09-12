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
Copy the `piv-agent` binary into your `$PATH`, and the `systemd` unit files to the correct location:

```
sudo cp piv-agent /usr/local/bin/
cp deploy/piv-agent.{socket,service} ~/.config/systemd/user/
systemctl --user daemon-reload
```

### Socket activation

`piv-agent` relies on [socket activation](https://0pointer.de/blog/projects/socket-activated-containers.html), and is currently only tested with `systemd`.
It doesn't listen to any sockets directly, and instead requires the init system to pass file descriptors to the `piv-agent` process after it is running.
This requirement makes it possible to exit the process when not in use.

`ssh-agent` and `gpg-agent` functionality are enabled by default in `piv-agent.service` and `piv-agent.socket`.
The index of the sockets listed in `piv-agent.socket` are indicated by the arguments to `--agent-types`.
