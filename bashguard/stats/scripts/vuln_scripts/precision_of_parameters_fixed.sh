#!/bin/bash
# Inspired by Orange Tsai

PATH=/usr/bin

WORKDIR=$(mktemp -p "$(mktemp -d /tmp/XXXXXXX)" -d XXXXXXXX) || exit 1
cd "$WORKDIR"

# some cleanup
HOME="$WORKDIR"
unset OLDPWD # thanks, WilyWizard

cp /flag "$WORKDIR"
read -r INPUT
[ "${#INPUT}" -gt 5 ] && exit 2
sh -c "$INPUT" < /dev/null