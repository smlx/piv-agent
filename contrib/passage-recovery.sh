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

# perform the bulk re-encryption using passage
export PASSAGE_IDENTITIES_FILE="/tmp/recovery/identity.txt"
passage reencrypt

echo "Bulk re-encryption complete."
