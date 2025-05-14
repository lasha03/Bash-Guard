#!/bin/bash

achi="$1"
lasha="$1"
lasa="$1"
fxala="$1"

foo () {
    achi="gio"
    lasha="gio"
    lasa="gio"
    fxala="gio"
}

myFunction () {
    achi="gio" 
    local lasha="gio"
    local deda="$1"

    foo () {
        lasa="gio"
        local fxala="ff"
    }
}

myFunction

foo # calls foo declared in myFunction

giorga="$1"
giorga="aaaa"

if [ condition1 ]; then
    gio="lasha"
else
    gio="$1"
fi

case $COUNTRY in

  Lithuania)
    echo -n "Lithuanian"
    ;;

  Romania | Moldova)
    echo -n "Romanian"
    ;;

  Italy | "San Marino" | Switzerland | "Vatican City")
    echo -n "Italian"
    ;;

  *)
    mama="$1"
    ;;
esac


