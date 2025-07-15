#!/bin/bash

PATH=/usr/bin

USER_INPUT=$1
MALICIOUS=$2

# These should be detected as command injection vulnerabilities
eval "$USER_INPUT"
bash -c "$MALICIOUS"

# This should also be vulnerable (command name from user input)
COMMAND=$3
$COMMAND 