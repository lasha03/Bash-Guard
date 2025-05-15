from pathlib import Path
from typing import List, Set, Dict
from bashguard.core.vulnerability import Recommendation
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.types import Command, UsedVariable, AssignedVariable

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
        
        # print("used vars", used_vars)
        # print("assigned vars", assigned_vars)
        # print("user input vars", self.user_input_vars)
        print("commands", commands)

        vulnerabilities = []
        for command in commands:
            vulnerabilities.extend(self._check_command_injection(command))
            vulnerabilities.extend(self._check_eval_source(command))
        
        return vulnerabilities
    
    def _check_command_injection(self, command: Command) -> List[Vulnerability]:
        vulnerabilities = []
        command_name = self.strip_quotes_and_dollar(command.name)
        if command_name in self.user_input_vars:
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.HIGH,
                description=Description.COMMAND_INJECTION,
                file_path=self.script_path,
                line_number=command.line,
                column=command.column,
                line_content=self.lines[command.line],
                recommendation=Recommendation.COMMAND_INJECTION
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    
    def _check_eval_source(self, cmd: Command) -> List[Vulnerability]:
        vulnerabilities = []

        if len(cmd.arguments) < 1:
            return vulnerabilities
        
        arg = self.strip_quotes_and_dollar(cmd.arguments[0])
        if cmd.name in ['eval', 'source'] and arg in self.user_input_vars:
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
        # Remove quotes if string starts and ends with them
        if s.startswith('"') and s.endswith('"') or s.startswith("'") and s.endswith("'"):
            s = s[1:-1]

        # Remove $ if it starts with it
        if s.startswith('$'):
            s = s[1:]
        
        return s

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