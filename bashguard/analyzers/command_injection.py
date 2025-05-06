from pathlib import Path
from typing import List, Set, Dict
from bashguard.core.vulnerability import Recommendation
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.types import UsedVariable, AssignedVariable

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
        self.var_assignments: Dict[str, List[AssignedVariable]] = {}  # Map of variable names to their assignments
    
    def analyze(self) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Get all variables used in the script
        used_vars = self.parser.get_used_variables()
        assigned_vars = self.parser.get_variables()
        # Build variable assignment map and find user input variables
        self._build_var_assignments(assigned_vars)
        self._find_user_input_variables(assigned_vars)
        
        # print("used vars", used_vars)
        # print("assigned vars", assigned_vars)
        # print("user input vars", self.user_input_vars)
        # print("var assignments", self.var_assignments)
        
        for var in used_vars:
            # Check for command substitution with unvalidated input
            vulnerabilities.extend(self._check_command_substitution(var))
            # Check for unquoted variables
            vulnerabilities.extend(self._check_unquoted_variables(var))
            # Check for eval/source commands
            vulnerabilities.extend(self._check_eval_source(var))
        
        return vulnerabilities
    
    # not used currently, (delete?)
    def _build_var_assignments(self, assigned_vars: List[AssignedVariable]):
        """Build a map of variable names to their assignments."""
        for var in assigned_vars:
            if var.name not in self.var_assignments:
                self.var_assignments[var.name] = []
            self.var_assignments[var.name].append(var)
    
    # might not be completely correct, but it's good enough for now
    def _find_user_input_variables(self, assigned_vars: List[AssignedVariable]):
        """Find all variables that come from user input, including indirect cases."""
        # First pass: find direct user input variables
        for var in assigned_vars:
            if self._is_direct_user_input(var.value):
                self.user_input_vars.add(var.name)
        
        # Second pass: find indirect user input variables
        changed = True
        while changed:
            changed = False
            for var in assigned_vars:
                if var.name not in self.user_input_vars:
                    if self._contains_user_input_var(var.value):
                        self.user_input_vars.add(var.name)
                        changed = True
    
    def _is_direct_user_input(self, value: str) -> bool:
        """Check if a value comes directly from user input."""
        # Check for command line arguments
        if any(f'${i}' in value for i in range(10)) or '$@' in value or '$*' in value:
            return True
        
        # Check for environment variables that might contain user input
        user_env_vars = ['$USER', '$HOME', '$PATH', '$SHELL', '$TERM', '$DISPLAY']
        if any(var in value for var in user_env_vars):
            return True

        # parser puts "user input" for read command. will change later
        if value == "user input":
            return True
        
        # there could be many other cases, but we don't care about them for now
        # # Check for read command
        # if 'read' in value:
        #     return True
        
        # # Check for process substitution with read
        # if '< <(' in value and 'read' in value:
        #     return True
        
        # # Check for command substitution that might contain user input
        # if '$(' in value or '`' in value:
        #     return True
        
        return False
    
    def _contains_user_input_var(self, value: str) -> bool:
        """Check if a value contains any variable that comes from user input."""
        # Extract all variables from the value
        vars_in_value = set()
        parts = value.split('$')
        for part in parts[1:]:  # Skip first part as it's before any $
            var_name = ''
            for char in part:
                if char.isalnum() or char == '_':
                    var_name += char
                else:
                    break
            if var_name:
                vars_in_value.add(var_name)
        
        # Check if any of these variables are known to come from user input
        return any(var in self.user_input_vars for var in vars_in_value)
    
    def _check_command_substitution(self, var: 'UsedVariable') -> List[Vulnerability]:
        vulnerabilities = []
        line = self.lines[var.line]
        
        # Check for command substitution with unvalidated input
        if '$(' in line or '`' in line:
            if var.name in self.user_input_vars or self._contains_user_input_var(var.name):
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description=Description.COMMAND_SUBSTITUTION,
                    file_path=self.script_path,
                    line_number=var.line,
                    column=var.column,
                    line_content=line,
                    recommendation=Recommendation.COMMAND_SUBSTITUTION
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_unquoted_variables(self, var: 'UsedVariable') -> List[Vulnerability]:
        vulnerabilities = []
        
        if not self._is_properly_quoted(var):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.UNQUOTED_VARIABLE,
                severity=SeverityLevel.HIGH,
                description=Description.UNQUOTED_VARIABLE,
                file_path=self.script_path,
                line_number=var.line,
                column=var.column,
                line_content=self.lines[var.line] if var.line < len(self.lines) else None,
                recommendation=Recommendation.UNQUOTED_VARIABLE
            )
            vulnerabilities.append(vulnerability)
        return vulnerabilities
    
    def _check_eval_source(self, var: 'UsedVariable') -> List[Vulnerability]:
        vulnerabilities = []

        line = self.lines[var.line]
        
        if line.strip().startswith('eval ') or line.strip().startswith('source '):
            if var.name in self.user_input_vars or self._contains_user_input_var(var.name):
                    vulnerability = Vulnerability(
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        severity=SeverityLevel.CRITICAL,
                        description=Description.EVAL_SOURCE,
                        file_path=self.script_path,
                        line_number=var.line,
                        column=0,
                        line_content=line,
                        recommendation=Recommendation.EVAL_SOURCE
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    # might be used in the future
    def _is_properly_double_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, '"')
    
    # might be used in the future
    def _is_properly_single_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, "'")
    
    def _is_properly_quoted(self, var: 'UsedVariable') -> bool:
        return self._is_properly_double_quoted(var) or self._is_properly_single_quoted(var)
    
    def __is_properly_quoted(self, var: 'UsedVariable', quote: str) -> bool:
        """Check if a variable is properly quoted in its usage."""
        line = self.lines[var.line]
        var_name = var.name
        
        # Find the variable in the line
        start = var.column
        end = start + len(var_name)
        
        before = line[:start].rstrip()
        after = line[end:].lstrip()
        
        # Check for proper quoting
        if before.endswith(quote) and after.startswith(quote):
            return True
        
        return False

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