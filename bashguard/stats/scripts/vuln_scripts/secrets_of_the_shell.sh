#!/bin/bash

PATH=/usr/bin

CHALLENGE=$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM
RESPONSE="$1"

# This disables command injection. If you can find a bypass of it, let Zardus know!
set -T
readonly BASH_SUBSHELL # props to HAL50000 for the bypass necessitating this fix
trap '[[ $BASH_SUBSHELL -gt 0 ]] && exit' DEBUG

if (( RESPONSE == CHALLENGE ))
then
	echo "Success! Here's part of the flag:"
	cat /flag | head -c10
else
	echo "Wrong!"
	cat /flag | md5sum
fi