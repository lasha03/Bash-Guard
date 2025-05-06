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
        
        for var in used_vars:
            # Check for command substitution with unvalidated input
            vulnerabilities.extend(self._check_command_substitution(var))
            # Check for unquoted variables
            vulnerabilities.extend(self._check_unquoted_variables(var))
            # Check for eval/source commands
            vulnerabilities.extend(self._check_eval_source(var))
        
        return vulnerabilities
    
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
        
        # there could be many other cases, but we don't care about them for now

        # # Check for read command
        # if 'read' in value:
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
            if var.name in self.user_input_vars:
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description="Command substitution with unvalidated input may lead to command injection",
                    file_path=self.script_path,
                    line_number=var.line,
                    column=var.column,
                    line_content=line,
                    recommendation="Validate and sanitize all input before using it in command substitution"
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
            if var.name in self.user_input_vars:
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

    # not used anymore
    def _contains_unvalidated_input(self, line: str) -> bool:
        """Check if a line contains potentially unvalidated input."""
        # Common sources of user input
        input_sources = [
            '$0', '$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8', '$9', '$@', '$*',  # Command line arguments
            '$USER', '$HOME', '$PATH', '$SHELL',  # Environment variables
            'read',  # Direct user input
            'curl', 'wget',  # Network input
            'cat', 'head', 'tail'  # File input
        ]
        
        return any(source in line for source in input_sources)