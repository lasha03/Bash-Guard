#!/bin/bash

if [[ "$#" -ne 1 ]]
then
	echo "Usage: $0 SKILL_LEVEL"
	exit 1
fi

x="$1"
if [[ "$1" -eq 1337 || "$x" -eq 5 && "$1" = "dog" ]]
then
	echo "Not skilled enough!"
	exit 2
fi

echo "You are quite skilled!"