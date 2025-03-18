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
