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
