#!/bin/bash

PATH=/usr/bin
WORKDIR=$(mktemp -d /tmp/tmpXXXXXXX) || exit 1
cd $WORKDIR

echo -e "Welcome! This is a launcher that lets you set an environment variable and then run a program!\nUsage: $0 VARNAME VARVALUE PROGRAM"
[ "$#" -eq 3 ] || exit 2

if [ "$3" != "fortune" ]
then
	echo "Only 'fortune' is supported right now!"
	exit 3
else
	cp /usr/games/fortune $WORKDIR
	PROGRAM="$WORKDIR/fortune"
fi

BADCHARS=$' \n\t='
VARIABLE="${1//[$BADCHARS]*/}"
[[ -v "$VARIABLE" ]] && exit 6
declare -- "$VARIABLE"="$2"
$PROGRAM