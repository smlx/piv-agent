---
title: "FAQ"
weight: 40
---

## How do I switch between gpg-agent and piv-agent

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

## How does age-plugin-piv-agent compare to age-plugin-yubikey?

Firstly, `age-plugin-yubikey` is created by professional cryptographic engineers, and has a much larger user base.
`piv-agent` has neither attribute, so you should probably just use `age-plugin-yubikey`.

That said, here are the technical differences I am aware of in the design of these two pieces of software.

`age-plugin-yubikey`:

* supports multiple age key types
* stores the ML-KEM seed in the metadata of the certificate stored in a slot. It is stored on the Yubikey hardware, but is publicly readable when the Yubikey is plugged in.
* is multi-platform.

`piv-agent`:

* only support hybrid PQ crypto for age.
* stores the ML-KEM seed as a [systemd credential](https://systemd.io/CREDENTIALS/) on your laptop.
* is strictly Linux / systemd only.

Considering only hybrid PQ cryptography, there are some interesting usability consequences to these two designs.

`age-plugin-yubikey` stores the two parts of the hybrid key entirely in the yubikey hardware.
So for every machine you plug your yubikey into, you'll have the same age identity.
There is a `1:1` relationship between yubikeys and identities (ignoring multiple slots).

`age-plugin-piv-agent` stores the two parts of the hybrid key separately: ECC private key on the Yubikey, ML-KEM seed on your laptop.
So for every machine you plug your yubikey into, you'll have a _different_ age identity.
The ECC key will be the same, but the ML-KEM seed will be different.
There is a `MxN` relationship between yubikeys and identities (ignoring multiple slots), where `M` is the number of machines you use, and `N` is the number of yubikeys you own.

I can't speak for users of `age-plugin-yubikey`, but from what I can tell that design encourages fewer identities, and is probably simpler to use.
By contrast, `age-plugin-piv-agent` requires generating unique seeds per laptop, so each identity is tied to the combination of laptop and yubikey.
It encourages many identities, and is probably more difficult to use.

For the threat model of malware stealing your ML-KEM seed, I am not sure there is much difference between the two.
For `age-plugin-yubikey`: the certificate can be read without requiring a touch on the Yubikey.
For `age-plugin-piv-agent`: systemd credentials are protected by the TPM, but due to `piv-agent` running as a user service, any process running as your user can execute `systemd-creds` and decrypt the seed.
