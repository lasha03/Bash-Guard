#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

read INPUT < <(head -n1 | tr -d "[A-Za-z0-9/]")
eval "$INPUT"