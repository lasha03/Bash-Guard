#!/bin/bash

PATH=/usr/bin

read FLAG < /flag
[[ "$FLAG" = $1 ]] && cat /flag
echo "Goodbye!"