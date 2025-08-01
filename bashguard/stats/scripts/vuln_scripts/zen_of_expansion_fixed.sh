#!/bin/bash

PATH=/usr/bin

pretty_cat () {
        HEADER="Here is /etc/passwd!"
        FILE="/etc/passwd"
        [ -n "$1" ] && HEADER="$1" && shift
        [ -n "$1" ] && FILE="$1" && shift

        echo "####### $HEADER ########"
        cat "$FILE"
}

[ "$#" -eq 1 ] || exit 1
pretty_cat "$*"