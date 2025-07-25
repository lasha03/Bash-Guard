#!/bin/bash

PATH=/usr/bin

PROPAGANDA=(
	"bash is good"
	"bash is great"
	"bash is wonderful"
)

INDEX="$1"
echo "Your chosen bash affirmation is: ${PROPAGANDA[$INDEX]}"