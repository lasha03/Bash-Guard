#!/bin/bash

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd "$WORKDIR"

doit() {
        echo -n ""
        read -r INPUT < <(head -n1 | tr -d "[A-Za-z./]")
        eval "$INPUT"
}

doit