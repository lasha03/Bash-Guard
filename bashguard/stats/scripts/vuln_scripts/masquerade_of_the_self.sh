#!/bin/bash


PATH=/usr/bin

case "$1" in
	"hi")
		echo hello
		;;
	"bye")
		echo ciao
		;;
	"help")
		echo "Usage: $0 ( hi | bye )"
		;;
	*)
		echo "Invalid command: $1"
		$0 help
		;;
esac