#!/bin/bash

PATH=/usr/bin

USER_INPUT=$1
MALICIOUS=$2

# These should be detected as command injection vulnerabilities
eval "eval '$USER_INPUT'"
bash -c "bash -c '$MALICIOUS'"
