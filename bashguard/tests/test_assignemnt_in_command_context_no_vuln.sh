#!/usr/bin/bash

PATH=/usr/bin

FOO="$1"
FOO="hello" bash -c '$FOO' # safe

BAR="hello"
BAR="$1" bash -c 'echo "$BAR"'
$BAR # safe

BAR="$1" bash -c "echo $BAR" # safe