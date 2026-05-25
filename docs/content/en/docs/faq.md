---
title: "FAQ"
weight: 40
---

## How does age-plugin-piv-agent compare to age-plugin-yubikey?

Firstly, `age-plugin-yubikey` is created by professional cryptographic engineers, and has a much larger user base.
`piv-agent` has neither attribute, so you should probably just use `age-plugin-yubikey`.

That said, here are the technical differences I am aware of in the design of these two pieces of software.

`age-plugin-yubikey`:

* supports multiple age key types
* stores the ML-KEM seed in the metadata of the certificate stored in a slot. It is stored on the YubiKey hardware, but is publicly readable when the YubiKey is plugged in.
* is multi-platform.

`piv-agent`:

* only support hybrid PQ crypto for age.
* stores the ML-KEM seed as a [systemd credential](https://systemd.io/CREDENTIALS/) on your laptop.
* is strictly Linux / systemd only.

Considering only hybrid PQ cryptography, there are some interesting usability consequences to these two designs.

`age-plugin-yubikey` stores the two parts of the hybrid key entirely in the YubiKey hardware.
So for every machine you plug your YubiKey into, you'll have the same age identity.
There is a `1:1` relationship between YubiKey slots and identities.

`age-plugin-piv-agent` stores the two parts of the hybrid key separately: ECC private key on the YubiKey, ML-KEM seed on your laptop.
So for every machine you plug your YubiKey into, you'll have a _different_ age identity.
The ECC key will be the same, but the ML-KEM seed will be different.
There is a `MxN` relationship between YubiKey slots and identities, where `M` is the number of machines you use, and `N` is the number of YubiKeys you own.

I can't speak for users of `age-plugin-yubikey`, but from what I can tell that design encourages fewer identities, and is probably simpler to use.
By contrast, `age-plugin-piv-agent` requires generating unique seeds per laptop, so each identity is tied to the combination of laptop and YubiKey slot.
It encourages many identities, and is probably more difficult to use.

For the threat model of malware stealing your ML-KEM seed, I am not sure there is much difference between the two.
For `age-plugin-yubikey`: the certificate can be read without requiring a touch on the YubiKey.
For `age-plugin-piv-agent`: systemd credentials are protected by the TPM, but due to `piv-agent` running as a user service, any process running as your user can execute `systemd-creds` and decrypt the seed.
