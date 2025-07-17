#!/usr/bin/bash

PATH=/usr/bin

FOO="hello"
FOO="$1" bash -c 'echo "$FOO"'

$FOO