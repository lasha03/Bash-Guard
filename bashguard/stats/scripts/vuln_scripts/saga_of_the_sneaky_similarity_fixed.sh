#!/bin/bash

PATH=/usr/bin
CHALLENGE="$RANDOM$RANDOM$RANDOM"

[ -n "$1" ] || exit 1
[ "$1" -eq "$CHALLENGE" ] && cat /flag
echo "Goodbye!"