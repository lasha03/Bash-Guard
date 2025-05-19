#!/bin/bash

PATH=/usr/bin

[ "$1" == "ping" ] && echo "pinged!" && read && "$0" pong
[ "$1" == "pong" ] && echo "ponged!"

# Parameter expansion
a="$1" # tainted
b="${1}" # tainted

c="none"
d="${c}" # not tainted
