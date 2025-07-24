#!/usr/bin/bash

set -euo pipefail

DEST=$HOME/bashguard/bash_test_dataset
mkdir -p "$DEST"
cd "$DEST"

while read -r repo; do
	    git clone --depth 1 "$repo"
done <<'REPOLIST'
https://github.com/awesome-lists/awesome-bash.git
https://github.com/dylanaraps/pure-bash-bible.git
https://github.com/alexanderepstein/Bash-Snippets.git
https://github.com/mathiasbynens/dotfiles.git
https://github.com/chelseakomlo/shellshock_demo.git
https://github.com/pbr94/Shellshock-Bash-Remote-Code-Execution-Vulnerability-and-Exploitation.git
https://github.com/xdistro/ShellShock.git
https://github.com/ice-wzl/bash-malware-dropper.git
https://github.com/0xjet/bash-malware.git
https://github.com/VincenzoArceri/bash-virus.git
https://github.com/greyhat-academy/malbash.git
https://github.com/anordal/shellharden.git
https://github.com/ruanyf/simple-bash-scripts.git
https://github.com/matthewreagan/BashSnippets.git
https://github.com/Chocapikk/CVE-2022-44877.git
https://github.com/shamo0/CVE-2024-6387_PoC.git
https://github.com/alex14324/ssh_poc2024.git
https://github.com/turbobit/CVE-2024-6387-OpenSSH-Vulnerability-Checker.git
REPOLIST

echo "Repositories cloned into $DEST"

bash_scripts=$(mktemp)

find "$DEST" -type f | while read -r file; do
  if [[ "$file" == *.sh ]]; then
    echo "$file"
  else
    if head -n 1 "$file" 2>/dev/null | grep -qE '^#!.*bash'; then
      echo "$file"
    fi
  fi
done > "$bash_scripts"

grep -Ei 'shellshock|cve|malware|virus|poc|dropper' < "$bash_scripts" > vulnerable.list

grep -vFf vulnerable.list "$bash_scripts" > secure.list

rm "$bash_scripts"

echo "Found $(wc -l < vulnerable.list) vulnerable bash scripts for testing"
echo "Found $(wc -l < secure.list) secure bash scripts for testing"

