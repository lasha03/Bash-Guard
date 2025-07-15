import re

from pathlib import Path
from typing import List, Set
from bashguard.core.vulnerability import Recommendation
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.types import Command, InjectableVariable, DeclaredPair

class CommandInjectionAnalyzer(BaseAnalyzer):
    """
    Analyzer for Command Injection vulnerabilities.
    Detects potential command injection vulnerabilities in bash scripts by checking for:
    - Unquoted variables in command execution
    - Command substitution with unvalidated input
    - eval/source commands with unvalidated input
    - Direct command execution with user input
    """

    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        super().__init__(script_path, content, parser, verbose)
        self.user_input_vars: Set[str] = set()  # Set of variables that come from user input


    def analyze(self) -> List[Vulnerability]:
        # Get all variables used in the script
        commands = self.parser.get_commands()
        # find user-inputted variables
        self.user_input_vars = self.parser.get_tainted_variables()
        
        for i in range(1, 10):
            self.user_input_vars.add(str(i))
        
        # print("used vars", used_vars)
        # print("assigned vars", assigned_vars)
        # print("user input vars", self.user_input_vars)
        # print("commands", commands)

        vulnerabilities = []
        for command in commands:
            vulnerabilities.extend(self._check_command_injection(command))
            vulnerabilities.extend(self._check_eval_source(command))
        
        vulnerabilities.extend(self._check_array_index_attacks())

        vulnerabilities.extend(self._check_superweapon_attack())

        # Disabled: Variable assignments are not command injection by themselves
        # vulnerabilities.extend(self._check_declared_pairs())
        # print(vulnerabilities)
        
        return vulnerabilities

    def _check_declared_pairs(self) -> List[Vulnerability]:
        """
        Check for declared pairs of variables that might be used in command injection attacks.
        
        Returns:
            List[Vulnerability]: List of detected command injection vulnerabilities
        """
        vulnerabilities = []

        for pair in self.parser.get_declared_pairs():
            var1 = pair.var1
            var2 = pair.var2
            if var1 in self.user_input_vars or var2 in self.user_input_vars:
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description=Description.COMMAND_INJECTION,
                    file_path=self.script_path,
                    line_number=pair.line,
                    column=pair.column,
                    recommendation=Recommendation.COMMAND_INJECTION
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _check_superweapon_attack(self) -> List[Vulnerability]:
        """
        Check which variables might be injectable by [`<flag`] attack.

        Returns:
            List[Vulnerability]: List of detected array index attack vulnerabilities
        """
        vulnerabilities = []

        injectable_variables = self.parser.get_injectable_variables()
        # print(injectable_variables)
        for var in injectable_variables:
            var_name = var.name
            if var_name in self.user_input_vars:
                # Check if the variable is properly quoted in its context
                if var.line < len(self.lines):
                    line_content = self.lines[var.line]
                    # Skip if the variable appears to be properly quoted
                    # Look for patterns like "${var}" or "${#var}" which are safe
                    if f'"${{{var_name}' in line_content or f'"${{#{var_name}' in line_content:
                        continue
                    
                    # Skip numeric comparisons and basic test conditions that should be treated as variable expansion
                    # These are unquoted variable issues, not command injection
                    import re
                    if re.search(r'\$' + var_name + r'\s*-[a-z]+\s*', line_content):  # -eq, -ne, -gt, etc.
                        continue
                        
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description=Description.COMMAND_INJECTION,
                    file_path=self.script_path,
                    line_number=var.line,
                    column=var.column,
                    line_content=self.lines[var.line] if var.line < len(self.lines) else None,
                    recommendation=Recommendation.ARRAY_INDEX_ATTACK
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _check_array_index_attacks(self) -> List[Vulnerability]:
        """
        Check for array index attacks in the script, specifically, user-controlled variables in array indices.
        
        Returns:
            List[Vulnerability]: List of detected array index attack vulnerabilities
        """
        vulnerabilities = []
        
        subscripts = self.parser.get_subscripts()
        # print(subscripts)
        
        for subscript in subscripts:
            for var in self.user_input_vars:
                if f'${var}' in subscript.index_expression:
                    # Check if subscript uses 0-indexed or 1-indexed line numbers
                    if subscript.line < len(self.lines):
                        line_content = self.lines[subscript.line]
                        line_number = subscript.line
                    else:
                        # Subscript might be 1-indexed, try subscript.line-1
                        line_content = self.lines[subscript.line-1] if subscript.line-1 < len(self.lines) else ""
                        line_number = subscript.line-1
                    
                    vulnerability = Vulnerability(
                        vulnerability_type=VulnerabilityType.ARRAY_INDEX_ATTACK,
                        severity=SeverityLevel.HIGH,
                        description=Description.ARRAY_INDEX_ATTACK,
                        file_path=self.script_path,
                        line_number=line_number,
                        column=subscript.column,
                        line_content=line_content,
                        recommendation=Recommendation.ARRAY_INDEX_ATTACK
                    )
                    vulnerabilities.append(vulnerability)
                    break
        
        return vulnerabilities
    
    def _check_command_injection(self, command: Command) -> List[Vulnerability]:
        vulnerabilities = []
        command_name = self.strip_quotes_and_dollar(command.name)
        
        # Check for direct variable execution (any variable used as a command)
        # This includes both user-controlled variables and variables that might be indirectly manipulated
        original_name = command.name
        is_variable_command = (original_name.startswith('$') or 
                             command_name in self.user_input_vars or
                             # Check if this is a variable name (not a standard command)
                             (command_name.isalpha() and command_name.isupper()))
        
        if is_variable_command:
            # Get the line content to verify this is a real command injection
            line_content = self.lines[command.line] if command.line < len(self.lines) else ""
            
            # Skip shebang lines and other non-command contexts
            if line_content.startswith('#!') or not line_content.strip():
                return vulnerabilities
            
            # Skip variable assignments (e.g., foo="$1")
            if f'{command_name}=' in line_content:
                return vulnerabilities
            
            # Skip if this is just a standalone variable name (likely from recursive parsing artifacts)
            if (command_name == line_content.strip() and 
                len(command.arguments) == 0 and 
                command.line < len(self.lines)):
                return vulnerabilities
                
            # Skip common system commands that are not variables
            system_commands = {'cd', 'echo', 'exit', 'cp', 'mv', 'rm', 'ls', 'cat', 'grep', 'find', 'mktemp'}
            if command_name.lower() in system_commands:
                return vulnerabilities
                
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.HIGH,
                description=Description.COMMAND_INJECTION,
                file_path=self.script_path,
                line_number=command.line,
                column=command.column,
                line_content=line_content,
                recommendation=Recommendation.COMMAND_INJECTION
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    
    def _check_eval_source(self, cmd: Command) -> List[Vulnerability]:
        vulnerabilities = []

        if len(cmd.arguments) < 1:
            return vulnerabilities

        
        command_name = cmd.name.rsplit('.', 1)[-1]
        
        # For sh -c and bash -c, check the second argument (the command to execute)
        if command_name in ['sh', 'bash'] and len(cmd.arguments) >= 2 and cmd.arguments[0] == '-c':
            arg = self.strip_quotes_and_dollar(cmd.arguments[1])
            # For bash/sh -c, only detect as command injection if the ENTIRE argument content is just a user input variable
            # This avoids conflicts with variable expansion detection for cases like 'echo $FOO'
            original_arg = cmd.arguments[1].strip('\'"')
            if arg in self.user_input_vars and original_arg in [f'${arg}', f'${{{arg}}}']:
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    description=Description.EVAL_SOURCE,
                    file_path=self.script_path,
                    line_number=cmd.line,
                    column=cmd.column,
                    line_content=self.lines[cmd.line],
                    recommendation=Recommendation.EVAL_SOURCE
                )
                vulnerabilities.append(vulnerability)
            return vulnerabilities
        else:
            arg = self.strip_quotes_and_dollar(cmd.arguments[0])
            
        # print(command_name, arg, arg in self.user_input_vars)
        if command_name in ['eval', 'source'] and arg in self.user_input_vars:
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.CRITICAL,
                description=Description.EVAL_SOURCE,
                file_path=self.script_path,
                line_number=cmd.line,
                column=cmd.column,
                line_content=self.lines[cmd.line],
                recommendation=Recommendation.EVAL_SOURCE
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    # remove '$' and quotes from the command name
    @staticmethod
    def strip_quotes_and_dollar(s: str) -> str:
        return s.strip('"\'').lstrip('$')

    # currently not used, but might be used in the future with a more sophisticated approach
    def _is_user_input_argument(self, line: str) -> bool:
        """
        Check if a line contains user input that could be used as a command argument.
        Returns True if the line contains any pattern that indicates user input.
        """
        # Direct user input commands
        user_input_commands = [
            'read',           # Direct read from stdin
            'getopts',        # Command line option parsing
            'select',         # Interactive menu selection
            'dialog',         # Text user interface
            'zenity',         # GTK+ dialog boxes
            'whiptail',       # Text user interface
            'curl',           # Network input
            'wget',           # Network input
            'nc',             # Network input
            'netcat',         # Network input
            'ftp',            # Network input
            'scp',            # Network input
            'rsync',          # Network input
            'ssh',            # Network input
            'telnet',         # Network input
        ]

        # File operations that might read user-controlled files
        file_operations = [
            'cat',            # File reading
            'head',           # File reading
            'tail',           # File reading
            'less',           # File reading
            'more',           # File reading
            'grep',           # File searching
            'sed',            # File editing
            'awk',            # File processing
            'cut',            # File processing
            'sort',           # File processing
            'uniq',           # File processing
            'join',           # File processing
            'paste',          # File processing
            'split',          # File processing
            'tr',             # Character translation
        ]

        # Process substitution and command substitution
        substitutions = [
            '< <(',           # Process substitution
            '> >(',           # Process substitution
            '$(',             # Command substitution
            '`',              # Command substitution (backticks)
        ]

        # Environment variables that might contain user input
        env_vars = [
            '$USER',          # Username
            '$HOME',          # Home directory
            '$PATH',          # Executable path
            '$SHELL',         # Shell
            '$TERM',          # Terminal type
            '$DISPLAY',       # X display
            '$SSH_CLIENT',    # SSH client info
            '$SSH_CONNECTION', # SSH connection info
            '$SSH_TTY',       # SSH TTY
            '$TMPDIR',        # Temporary directory
            '$TEMP',          # Temporary directory
            '$TMP',           # Temporary directory
            '$PWD',           # Current directory
            '$OLDPWD',        # Previous directory
            '$CDPATH',        # CD path
            '$IFS',           # Internal field separator
            '$PS1',           # Primary prompt
            '$PS2',           # Secondary prompt
            '$PS3',           # Select prompt
            '$PS4',           # Debug prompt
        ]

        # Command line arguments
        cmd_args = [f'${i}' for i in range(10)] + ['$@', '$*']

        # Check for any of these patterns in the line
        patterns = (
            user_input_commands +
            file_operations +
            substitutions +
            env_vars +
            cmd_args
        )

        # Check for the patterns
        for pattern in patterns:
            if pattern in line:
                return True

        # Check for process substitution with any command
        if '< <(' in line:
            # Extract the command inside process substitution
            start = line.find('< <(') + 4
            end = line.find(')', start)
            if end != -1:
                inner_cmd = line[start:end]
                # Check if inner command contains any user input patterns
                if any(pattern in inner_cmd for pattern in patterns):
                    return True

        # Check for command substitution with any command
        if '$(' in line:
            # Extract the command inside command substitution
            start = line.find('$(') + 2
            end = line.find(')', start)
            if end != -1:
                inner_cmd = line[start:end]
                # Check if inner command contains any user input patterns
                if any(pattern in inner_cmd for pattern in patterns):
                    return True

        # Check for backtick command substitution
        if '`' in line:
            # Extract the command inside backticks
            start = line.find('`') + 1
            end = line.find('`', start)
            if end != -1:
                inner_cmd = line[start:end]
                # Check if inner command contains any user input patterns
                if any(pattern in inner_cmd for pattern in patterns):
                    return True

        return False