#!/bin/bash
set -e

# ensure /tmp is a tmpfs
if ! findmnt /tmp -t tmpfs >/dev/null; then
	echo "/tmp is not a tmpfs"
	exit 1
fi

# ensure zbarcam is installed
if ! type zbarcam >/dev/null 2>&1; then
	echo "zbarcam is not installed"
	exit 1
fi

# ensure passage is installed
if ! type passage >/dev/null 2>&1; then
	echo "passage is not installed"
	exit 1
fi

# ensure age-keygen is installed
if ! type age-keygen >/dev/null 2>&1; then
	echo "age-keygen is not installed"
	exit 1
fi

# ensure clean up on exit
trap 'rm -rf /tmp/recovery && echo "Wiped identity."' EXIT

# create a recovery directory
mkdir -p /tmp/recovery
chmod 700 /tmp/recovery

VIDEO_DEVICE=${1:-}

echo "Please show the break-glass QR code to your webcam..."

# scan the QR code (hold your phone to the webcam)
if [ "$VIDEO_DEVICE" != "" ]; then
	zbarcam --raw --quiet --oneshot "$VIDEO_DEVICE" >/tmp/recovery/identity.txt
else
	zbarcam --raw --quiet --oneshot >/tmp/recovery/identity.txt
fi
echo "QR Code successfully scanned."

PASSAGE_DIR="${PASSAGE_DIR:-$HOME/.passage/store}"
PUBLIC_KEY=$(age-keygen -y /tmp/recovery/identity.txt)

if ! grep -q "^$PUBLIC_KEY\$" "$PASSAGE_DIR/.age-recipients"; then
	echo "The scanned identity is not in $PASSAGE_DIR/.age-recipients."
	echo "If you do not add it, the operation will be aborted because otherwise the store will no longer be decryptable by the recovery identity!"
	read -p "Do you want to add it? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo "Adding recovery identity to $PASSAGE_DIR/.age-recipients"
		echo "$PUBLIC_KEY" >>"$PASSAGE_DIR/.age-recipients"
	else
		echo "Aborting."
		exit 1
	fi
fi

# perform the bulk re-encryption using passage
export PASSAGE_IDENTITIES_FILE="/tmp/recovery/identity.txt"
passage reencrypt

echo "Bulk re-encryption complete."
