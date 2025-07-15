#!/bin/bash

PATH=/usr/bin

# This should be SAFE: FOO is set to literal "hello" for this command only
FOO=hello bash -c 'echo "$FOO"'

# This should also be SAFE: Multiple assignments with literal values
USER=admin PASS=secret bash -c 'echo "$USER:$PASS"' 