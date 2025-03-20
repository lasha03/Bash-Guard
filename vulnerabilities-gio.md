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
