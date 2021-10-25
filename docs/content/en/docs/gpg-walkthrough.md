---
title: "GPG Walkthrough"
weight: 50
description: Full example of how you might set up and use piv-agent with gpg.
---

## Overview

GnuPG being a complex piece of software, setup with `piv-agent` is a bit fiddly.
This example is intended to illustrate how `piv-agent` can integrate with existing GnuPG keys and workflows.

{{% alert title="Note" %}}
This example requires switching between `gpg-agent` and `piv-agent`.
See the [FAQ](../../docs/faq) for how to do that.
{{% /alert %}}

## Setup

Suppose I have an existing RSA OpenPGP key that I use with `gpg`.
Creation of a `gpg` key is outside the scope of this document, but there are reasonable instructions [here](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key).

With `gpg-agent` running, listing the RSA key looks something like this:

```
$ gpg --list-secret-keys --keyid-format=long --with-keygrip
/home/scott/.gnupg/pubring.kbx
------------------------------
sec   rsa3072/EC26B2E4240DD2A9 2021-10-17 [SC]
      9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
      Keygrip = C284C191A1EA87796F4FE7159DD274A5D6CEADCC
uid                 [ultimate] Scott Leggett (piv-agent documentation example) <scott@sl.id.au>
ssb   rsa3072/42B99C3339C9FBC1 2021-10-17 [E]
      Keygrip = 5B918C31D4419A0D69873CB6562635C68211B872
```

Now we can add cryptographic subkeys stored on the Yubikey, to this RSA key,  for use with `piv-agent`.

### Export RSA keyfiles

Lets export the private keys of the existing RSA keypairs so that they can be used in a fallback capacity by `piv-agent`:

```
umask 77; mkdir -p ~/.gnupg/piv-agent.secring
gpg --export-secret-key 0xEC26B2E4240DD2A9 > ~/.gnupg/piv-agent.secring/EC26B2E4240DD2A9.gpg
```

### Setup Yubikey

Now lets set up the Yubikey with new cryptographic keys.

```
# get the name of the card
$ piv-agent list
Security keys (cards):
Yubico YubiKey FIDO+CCID 01 00
...
# use the card name to setup the Yubikey
$ piv-agent setup --card="Yubico YubiKey FIDO+CCID 01 00" --pin=123456 --reset-security-key
```

List the keys that were just generated.
This command will require entering the pin specified above, and touching the device twice.

{{% alert title="Note" %}}
You might want to customize the UserID embedded in the public keys using `--pgp-name` and `--pgp-email`.
See `piv-agent list --help`.
{{% /alert %}}

```
$ piv-agent list --key-formats=gpg
Security keys (cards):
Yubico YubiKey FIDO+CCID 01 00

Signing GPG Keys:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: always

xlIEYWvCQBMIKoZIzj0DAQcCAwSfEgRY/gnycErhFQMiij9SWlNZdkVKPPHRum8k
vnY1iE8kddErPVECabFGA22RRxaf/OJ5j9TLeGu3dTWPc2hPzUxwaXYtYWdlbnQg
KHBpdi1hZ2VudCBzaWduaW5nIGtleTsgdG91Y2gtcG9saWN5IGFsd2F5cykgPG5v
cmVwbHlAZXhhbXBsZS5jb20+wmEEExMIABMFAmFrwkAJEDSxvJa0+5T5AhsDAACh
mgD/W0BCIX0tnb2FyRfyvqpdf1245K+50UjegNrADmJkNJwA/RaELw5wd7UVNsln
/mef4Qwjp5HY6Rf6MM+uBCJ4gyT2
=CUFl
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: never

xlIEYWvCQBMIKoZIzj0DAQcCAwRRAjG1CSVLz55xWr7yA19Fw4uJQrRLEgCzB8f+
1EpM/gEM54VpcUZgr6+cIkRUwuU+lIOdlQhReQv9mqPWdcK5zUtwaXYtYWdlbnQg
KHBpdi1hZ2VudCBzaWduaW5nIGtleTsgdG91Y2gtcG9saWN5IG5ldmVyKSA8bm9y
ZXBseUBleGFtcGxlLmNvbT7CYQQTEwgAEwUCYWvCQAkQYerbn6tx7bECGwMAAKg3
AQDwbcR4ZklLha63wZwLYDkO4CNwRw8m8595OoabXq2g9QEAtU9MErWpO7un6GGG
tmEz6vJ2n1aPlNzxEFWkJHlq0F4=
=KYaq
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: cached

xlIEYWvCQBMIKoZIzj0DAQcCAwQ3pyIrqKjEdG3fqtxzJwlhsavnOzDxRsP4ttnz
Jvj20ilmWVEwuy9SRraL40KMAf//LbtsfDF7JaPIsrKTDFN2zUxwaXYtYWdlbnQg
KHBpdi1hZ2VudCBzaWduaW5nIGtleTsgdG91Y2gtcG9saWN5IGNhY2hlZCkgPG5v
cmVwbHlAZXhhbXBsZS5jb20+wmEEExMIABMFAmFrwkAJEAJzIXQG9KHGAhsDAACf
mAD+O9CAKvL52t8FNM1OrfLXBiKNibaYAb46Xk+9cHlYm90A/2OiyDBkz1fbJoEk
1Lg4AaxcNwsmPoVRMeBCXZtIndrB
=8dJl
-----END PGP PUBLIC KEY BLOCK-----

Decrypting GPG Keys:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: never

xlIEYWvCQBMIKoZIzj0DAQcCAwTHYPdFNeoy25gUFmfpi+8UYSmfWPY/YhVbwddx
ANiAQk5+nKOoAt7oucyo2IJZMgs8Rst3NLtDCDXMhPZhpBqqzU5waXYtYWdlbnQg
KHBpdi1hZ2VudCBkZWNyeXB0aW5nIGtleTsgdG91Y2gtcG9saWN5IG5ldmVyKSA8
bm9yZXBseUBleGFtcGxlLmNvbT7CYQQTEwgAEwUCYWvCQAkQFbVY84tuH9gCGwMA
ABxTAQCFK2wLxDhU5LzetlVZhTKIBi9d9h8y3/qucrZfJ/9PUQD8DG2P+S7eGSiR
blIZt6TzPLANPgND/rsiRE/Fae9VcqE=
=X7df
-----END PGP PUBLIC KEY BLOCK-----
$
```

### Import Yubikey cryptographic keys

Import the public keys for the slots you are interested in, into `gpg`.

```
gpg --import <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: never

xlIEYWvCQBMIKoZIzj0DAQcCAwRRAjG1CSVLz55xWr7yA19Fw4uJQrRLEgCzB8f+
1EpM/gEM54VpcUZgr6+cIkRUwuU+lIOdlQhReQv9mqPWdcK5zUtwaXYtYWdlbnQg
KHBpdi1hZ2VudCBzaWduaW5nIGtleTsgdG91Y2gtcG9saWN5IG5ldmVyKSA8bm9y
ZXBseUBleGFtcGxlLmNvbT7CYQQTEwgAEwUCYWvCQAkQYerbn6tx7bECGwMAAKg3
AQDwbcR4ZklLha63wZwLYDkO4CNwRw8m8595OoabXq2g9QEAtU9MErWpO7un6GGG
tmEz6vJ2n1aPlNzxEFWkJHlq0F4=
=KYaq
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Yubico YubiKey FIDO+CCID 01 00 #11577026, touch policy: never

xlIEYWvCQBMIKoZIzj0DAQcCAwTHYPdFNeoy25gUFmfpi+8UYSmfWPY/YhVbwddx
ANiAQk5+nKOoAt7oucyo2IJZMgs8Rst3NLtDCDXMhPZhpBqqzU5waXYtYWdlbnQg
KHBpdi1hZ2VudCBkZWNyeXB0aW5nIGtleTsgdG91Y2gtcG9saWN5IG5ldmVyKSA8
bm9yZXBseUBleGFtcGxlLmNvbT7CYQQTEwgAEwUCYWvCQAkQFbVY84tuH9gCGwMA
ABxTAQCFK2wLxDhU5LzetlVZhTKIBi9d9h8y3/qucrZfJ/9PUQD8DG2P+S7eGSiR
blIZt6TzPLANPgND/rsiRE/Fae9VcqE=
=X7df
-----END PGP PUBLIC KEY BLOCK-----
EOF
gpg: key 61EADB9FAB71EDB1: public key "piv-agent (piv-agent signing key; touch-policy never) <noreply@example.com>" imported
gpg: key 15B558F38B6E1FD8: public key "piv-agent (piv-agent decrypting key; touch-policy never) <noreply@example.com>" imported
gpg: Total number processed: 2
gpg:               imported: 2
```

Listing the public keys known to `gpg` now shows the new keys.

```
$ gpg --list-keys --keyid-format=long --with-keygrip
/home/scott/.gnupg/pubring.kbx
------------------------------
pub   rsa3072/EC26B2E4240DD2A9 2021-10-17 [SC]
      9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
      Keygrip = C284C191A1EA87796F4FE7159DD274A5D6CEADCC
uid                 [ultimate] Scott Leggett (piv-agent documentation example) <scott@sl.id.au>
sub   rsa3072/42B99C3339C9FBC1 2021-10-17 [E]
      Keygrip = 5B918C31D4419A0D69873CB6562635C68211B872

pub   nistp256/61EADB9FAB71EDB1 2021-10-17 [SC]
      C0DDA160CE064B915F85611C61EADB9FAB71EDB1
      Keygrip = 635FB47CEDA6B1C52F6E13AC5CC83629CB740CA1
uid                 [ unknown] piv-agent (piv-agent signing key; touch-policy never) <noreply@example.com>

pub   nistp256/15B558F38B6E1FD8 2021-10-17 [SC]
      4AB8F06DBC18A54D056D15F315B558F38B6E1FD8
      Keygrip = 2925C2C0CAA1752F6F162BD68786EF020CF464F8
uid                 [ unknown] piv-agent (piv-agent decrypting key; touch-policy never) <noreply@example.com>
```

But no secret keys yet.

```
$ gpg --list-secret-keys --keyid-format=long --with-keygrip
/home/scott/.gnupg/pubring.kbx
------------------------------
sec   rsa3072/EC26B2E4240DD2A9 2021-10-17 [SC]
      9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
      Keygrip = C284C191A1EA87796F4FE7159DD274A5D6CEADCC
uid                 [ultimate] Scott Leggett (piv-agent documentation example) <scott@sl.id.au>
ssb   rsa3072/42B99C3339C9FBC1 2021-10-17 [E]
      Keygrip = 5B918C31D4419A0D69873CB6562635C68211B872
```

Stop `gpg-agent`, start `piv-agent`, and list secret keys again.
Now the cryptographic keys stored on the Yubikey are available.

```
$ gpg --list-secret-keys --keyid-format=long --with-keygrip
/home/scott/.gnupg/pubring.kbx
------------------------------
sec   rsa3072/EC26B2E4240DD2A9 2021-10-17 [SC]
      9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
      Keygrip = C284C191A1EA87796F4FE7159DD274A5D6CEADCC
uid                 [ultimate] Scott Leggett (piv-agent documentation example) <scott@sl.id.au>
ssb   rsa3072/42B99C3339C9FBC1 2021-10-17 [E]
      Keygrip = 5B918C31D4419A0D69873CB6562635C68211B872

sec   nistp256/61EADB9FAB71EDB1 2021-10-17 [SC]
      C0DDA160CE064B915F85611C61EADB9FAB71EDB1
      Keygrip = 635FB47CEDA6B1C52F6E13AC5CC83629CB740CA1
uid                 [ unknown] piv-agent (piv-agent signing key; touch-policy never) <noreply@example.com>

sec   nistp256/15B558F38B6E1FD8 2021-10-17 [SC]
      4AB8F06DBC18A54D056D15F315B558F38B6E1FD8
      Keygrip = 2925C2C0CAA1752F6F162BD68786EF020CF464F8
uid                 [ unknown] piv-agent (piv-agent decrypting key; touch-policy never) <noreply@example.com>
```

### Add decrypting subkey

Now we can add the piv-agent decrypting key as a subkey of the RSA master key.

```
$ gpg --expert --edit-key 0xEC26B2E4240DD2A9
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Secret key is available.

sec  rsa3072/EC26B2E4240DD2A9
     created: 2021-10-17  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
ssb  rsa3072/42B99C3339C9FBC1
     created: 2021-10-17  expires: never       usage: E   
[ultimate] (1). Scott Leggett (piv-agent documentation example) <scott@sl.id.au>

gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
  (14) Existing key from card
Your selection? 13
Enter the keygrip: 2925C2C0CAA1752F6F162BD68786EF020CF464F8

Possible actions for a ECDH key: Encrypt 
Current allowed actions: Encrypt 

   (E) Toggle the encrypt capability
   (Q) Finished

Your selection? q
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 
Key does not expire at all
Is this correct? (y/N) y
Really create? (y/N) y

sec  rsa3072/EC26B2E4240DD2A9
     created: 2021-10-17  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
ssb  rsa3072/42B99C3339C9FBC1
     created: 2021-10-17  expires: never       usage: E   
ssb  nistp256/84F7BF2FEAC32674
     created: 2021-10-17  expires: never       usage: E   
[ultimate] (1). Scott Leggett (piv-agent documentation example) <scott@sl.id.au>

gpg> save
```

### Add signing subkey

And we can add the piv-agent signing key as a subkey of the RSA master key too.

{{% alert title="Note" %}}
This doesn't currently work without a patch in GnuPG due to [this GnuPG bug](https://dev.gnupg.org/T5555).
The session below is with the patch from the bug report applied.
{{% /alert %}}

```
$ gpg --expert --edit-key 0xEC26B2E4240DD2A9
gpg (GnuPG) 2.3.2; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Secret key is available.

sec  rsa3072/EC26B2E4240DD2A9
     created: 2021-10-17  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
ssb  rsa3072/42B99C3339C9FBC1
     created: 2021-10-17  expires: never       usage: E   
ssb  nistp256/84F7BF2FEAC32674
     created: 2021-10-17  expires: never       usage: E   
[ultimate] (1). Scott Leggett (piv-agent documentation example) <scott@sl.id.au>

gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
  (14) Existing key from card
Your selection? 13
Enter the keygrip: 635FB47CEDA6B1C52F6E13AC5CC83629CB740CA1

Possible actions for this ECC key: Sign Authenticate 
Current allowed actions: Sign 

   (S) Toggle the sign capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? q
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 
Key does not expire at all
Is this correct? (y/N) y
Really create? (y/N) y

sec  rsa3072/EC26B2E4240DD2A9
     created: 2021-10-17  expires: never       usage: SC  
     trust: ultimate      validity: ultimate
ssb  rsa3072/42B99C3339C9FBC1
     created: 2021-10-17  expires: never       usage: E   
ssb  nistp256/84F7BF2FEAC32674
     created: 2021-10-17  expires: never       usage: E   
ssb  nistp256/3F086B69FEE7985B
     created: 2021-10-17  expires: never       usage: S   
[ultimate] (1). Scott Leggett (piv-agent documentation example) <scott@sl.id.au>

gpg> save
```

### Inspect subkeys

The cryptographic keys stored on the Yubikey are now subkeys of the RSA master key.

```
$ gpg --list-secret-keys --keyid-format=long --with-keygrip
/home/scott/.gnupg/pubring.kbx
------------------------------
sec   rsa3072/EC26B2E4240DD2A9 2021-10-17 [SC]
      9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
      Keygrip = C284C191A1EA87796F4FE7159DD274A5D6CEADCC
uid                 [ultimate] Scott Leggett (piv-agent documentation example) <scott@sl.id.au>
ssb   rsa3072/42B99C3339C9FBC1 2021-10-17 [E]
      Keygrip = 5B918C31D4419A0D69873CB6562635C68211B872
ssb   nistp256/84F7BF2FEAC32674 2021-10-17 [E]
      Keygrip = 2925C2C0CAA1752F6F162BD68786EF020CF464F8
ssb   nistp256/3F086B69FEE7985B 2021-10-17 [S]
      Keygrip = 635FB47CEDA6B1C52F6E13AC5CC83629CB740CA1

sec   nistp256/61EADB9FAB71EDB1 2021-10-17 [SC]
      C0DDA160CE064B915F85611C61EADB9FAB71EDB1
      Keygrip = 635FB47CEDA6B1C52F6E13AC5CC83629CB740CA1
uid                 [ unknown] piv-agent (piv-agent signing key; touch-policy never) <noreply@example.com>

sec   nistp256/15B558F38B6E1FD8 2021-10-17 [SC]
      4AB8F06DBC18A54D056D15F315B558F38B6E1FD8
      Keygrip = 2925C2C0CAA1752F6F162BD68786EF020CF464F8
uid                 [ unknown] piv-agent (piv-agent decrypting key; touch-policy never) <noreply@example.com>
```

## Use

Signing and encryption using the RSA master key ID will now preferentially use the cryptographic keys stored on the Yubikey, falling back to the keyfiles if the Yubikey is not available.
Specify the master key ID (e.g. `0x9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9` or `0xEC26B2E4240DD2A9`) to use the subkeys.
The subkey with the most recent date is preferred by `gpg`.

Importantly the master key ID is the same after adding the subkeys, so any existing workflows will continue to work as before.

### Publish public key

The public key can now be distributed to keyservers and other services such as Github.
The subkeys are included in the exported master public key.

```
$ gpg --export --armor 0xEC26B2E4240DD2A9
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
FZbaoApovI7Dy6J1Ewo0vTA=
=hNHV
-----END PGP PUBLIC KEY BLOCK-----
```

### Signing Example

With the Yubikey plugged in, the cryptographic key stored in hardware is used for signing.

```
$ echo bar > foo; gpg --output foo.sig --local-user 0xEC26B2E4240DD2A9 --sign foo
$ gpg --verify -v ./foo.sig
gpg: original file name='foo'
gpg: Signature made Sun 17 Oct 2021 15:48:16 AWST
gpg:                using ECDSA key 28D1AAA597866ABB0B5AFC553F086B69FEE7985B
gpg: using subkey 3F086B69FEE7985B instead of primary key EC26B2E4240DD2A9
gpg: using subkey 3F086B69FEE7985B instead of primary key EC26B2E4240DD2A9
gpg: using pgp trust model
gpg: Good signature from "Scott Leggett (piv-agent documentation example) <scott@sl.id.au>" [ultimate]
gpg: using subkey 3F086B69FEE7985B instead of primary key EC26B2E4240DD2A9
gpg: binary signature, digest algorithm SHA256, key algorithm nistp256
gpg: WARNING: not a detached signature; file './foo' was NOT verified!
```

With the Yubikey unplugged, the traditional keyfile is used for signing.

```
$ gpg --verify -v ./foo.sig
gpg: original file name='foo'
gpg: Signature made Sun 17 Oct 2021 16:16:32 AWST
gpg:                using RSA key 9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
gpg: using pgp trust model
gpg: Good signature from "Scott Leggett (piv-agent documentation example) <scott@sl.id.au>" [ultimate]
gpg: binary signature, digest algorithm SHA512, key algorithm rsa3072
gpg: WARNING: not a detached signature; file './foo' was NOT verified!
```

### Decrypting Example

Encryption also prefers the cryptographic key stored in hardware.

```
$ echo bar > foo; gpg --output foo.enc --recipient 0xEC26B2E4240DD2A9 --encrypt foo
$ gpg --decrypt -v ./foo.enc
gpg: public key is 84F7BF2FEAC32674
gpg: using subkey 84F7BF2FEAC32674 instead of primary key EC26B2E4240DD2A9
gpg: using subkey 84F7BF2FEAC32674 instead of primary key EC26B2E4240DD2A9
gpg: encrypted with 256-bit ECDH key, ID 84F7BF2FEAC32674, created 2021-10-17
      "Scott Leggett (piv-agent documentation example) <scott@sl.id.au>"
gpg: AES256 encrypted data
gpg: original file name='foo'
bar
```

You can also specify multiple key IDs when encrypting (one keyfile, one hardware), for fallback purposes.

```
$ echo bar > foo; gpg --output foo.enc --recipient 0x42B99C3339C9FBC1! --recipient 0x84F7BF2FEAC32674! --encrypt foo
$ gpg --decrypt -v ./foo.enc
gpg: public key is 42B99C3339C9FBC1
gpg: using subkey 42B99C3339C9FBC1 instead of primary key EC26B2E4240DD2A9
gpg: public key is 84F7BF2FEAC32674
gpg: using subkey 84F7BF2FEAC32674 instead of primary key EC26B2E4240DD2A9
gpg: encrypted with 256-bit ECDH key, ID 84F7BF2FEAC32674, created 2021-10-17
      "Scott Leggett (piv-agent documentation example) <scott@sl.id.au>"
gpg: using subkey 42B99C3339C9FBC1 instead of primary key EC26B2E4240DD2A9
gpg: encrypted with 3072-bit RSA key, ID 42B99C3339C9FBC1, created 2021-10-17
      "Scott Leggett (piv-agent documentation example) <scott@sl.id.au>"
gpg: AES256 encrypted data
gpg: original file name='foo'
bar
```

### Common software integration

#### git

The same master key ID will work as before, but signing will prefer to use the hardware security device if it is plugged in.

```
# example ~/.config/git/config
[user]
	name = Scott Leggett
	email = scott@sl.id.au
	signingKey = 9FA216008BDF1AE5E1BCAEC3EC26B2E4240DD2A9
[commit]
	gpgSign = true
```

#### pass

`pass` has the ability to encrypt to multiple key-ids.
Running `pass init` will re-encrypt existing passwords and configure `pass` to use the specified key-ids for encryption.
As usual, `piv-agent` will use the cryptographic key stored in hardware for decryption if it is available, but fall back to the keyfile otherwise.

```
pass init 0x42B99C3339C9FBC1! 0x84F7BF2FEAC32674!
```
