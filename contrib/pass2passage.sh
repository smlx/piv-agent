#!/usr/bin/env bash
set -eou pipefail
cd "${PASSWORD_STORE_DIR:-$HOME/.password-store}"
while read -r -d "" passfile; do
	name="${passfile#./}"
	name="${name%.gpg}"
	[[ -f "${PASSAGE_DIR:-$HOME/.passage/store}/$name.age" ]] && continue
	pass "$name" | passage insert -m "$name" || {
		passage rm "$name"
		break
	}
done < <(find . -path '*/.git' -prune -o -iname '*.gpg' -print0)
