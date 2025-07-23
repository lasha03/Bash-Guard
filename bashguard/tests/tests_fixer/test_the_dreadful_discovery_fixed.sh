#!/bin/bash

PATH=/usr/bin

CHALLENGE="$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM"
RESPONSE="$1"

# Can you see what HAL50000 saw?
set -T
#readonly BASH_SUBSHELL
trap '[[ $BASH_SUBSHELL -gt 0 ]] && exit' DEBUG

if (( RESPONSE == CHALLENGE && "$1" == CHALLENGE || 1 == 2))
then
	echo "Success!"
	#cat /flag
else
	echo "Wrong!"
	#cat /flag | md5sum
fi