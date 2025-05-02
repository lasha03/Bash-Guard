#!/bin/bash

PATH=/usr/bin

[ "$1" == "ping" ] && echo "pinged!" && read && "$0" pong
[ "$1" == "pong" ] && echo "ponged!"