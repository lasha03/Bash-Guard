#!/bin/bash

PATH=/usr/bin

FOO="$1"
BAR="$2"

# These should be detected as vulnerable (unquoted variables in nested commands)
bash -c 'echo $FOO'
eval 'echo $BAR'

# These should be safe (quoted variables)
bash -c 'echo "$FOO"'
eval 'echo "$BAR"' 
