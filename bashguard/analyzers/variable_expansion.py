"""
Analyzer for variable expansion vulnerabilities.
"""
from pathlib import Path
from typing import List
from bashguard.core.vulnerability import Recommendation
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.types import UsedVariable, AssignedVariable

class VariableExpansionAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects issues with variable expansion in shell scripts.
    
    It looks for potential vulnerabilities related to:
    - Unquoted variable expansions
    - Unquoted variable assignments 
    - Word splitting issues
    - Globbing problems with expanded variables
    - Missing default values for parameter expansions
    """
    
    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        """
        Initialize the variable expansion analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, parser, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for variable expansion vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        used_vars = self.parser.get_used_variables()
        assigned_vars = self.parser.get_variables()

        for var in used_vars:
            # Check for unquoted variables
            vulnerabilities.extend(self._check_unquoted_variables(var))
        
        for var in assigned_vars:
            # Check for unquoted variable assignments
            vulnerabilities.extend(self._check_unquoted_variable_assignments(var))
        
        return vulnerabilities

    def _check_unquoted_variables(self, var: 'UsedVariable') -> List[Vulnerability]:
        vulnerabilities = []
        
        # Skip $0 specifically as it's handled by ParameterExpansionAnalyzer
        # But keep $1, $2, etc. as they can have unquoted variable expansion issues
        var_name = var.name.lstrip('$').lstrip('{').rstrip('}')  # Remove $ and {} to get the actual variable name
        if var_name == '0':
            return vulnerabilities
        
        # Skip variables used as commands (at the beginning of a line)
        # These are acceptable practice for program execution
        if self._is_command_execution(var):
            return vulnerabilities
        
        if not self._is_properly_quoted(var):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.VARIABLE_EXPANSION,
                severity=SeverityLevel.HIGH,
                description=Description.VARIABLE_EXPANSION.value,
                file_path=self.script_path,
                line_number=var.line,
                column=var.column,
                line_content=self.lines[var.line] if var.line < len(self.lines) else None,
                recommendation=Recommendation.VARIABLE_EXPANSION
            )
            vulnerabilities.append(vulnerability)
        return vulnerabilities

    def _check_unquoted_variable_assignments(self, var: 'AssignedVariable') -> List[Vulnerability]:
        """Check if variable assignments contain unquoted variable expansions."""
        vulnerabilities = []
        
        # Check if the assigned value contains unquoted variable expansions
        if not var.value or not var.value.sensitive_parts:
            return vulnerabilities
            
        for sensitive_part in var.value.sensitive_parts:
            # Check if this sensitive part represents an unquoted variable expansion
            if hasattr(sensitive_part, 'variable'):
                # Get the line content to check for proper quoting
                if var.line < len(self.lines):
                    line_content = self.lines[var.line]
                    
                    # Check if this assignment is in a command context (like FOO=$1 bash ...)
                    # or a regular assignment context
                    if not self._is_assignment_value_quoted(var, sensitive_part, line_content):
                        # Use the column from the sensitive part (where the actual variable expansion is)
                        column = getattr(sensitive_part, 'column_frame', (var.column, var.column))[0]
                        vulnerability = Vulnerability(
                            vulnerability_type=VulnerabilityType.VARIABLE_EXPANSION,
                            severity=SeverityLevel.HIGH,
                            description=Description.VARIABLE_EXPANSION.value,
                            file_path=self.script_path,
                            line_number=var.line,
                            column=column,
                            line_content=line_content,
                            recommendation=Recommendation.VARIABLE_EXPANSION
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_assignment_value_quoted(self, var: 'AssignedVariable', sensitive_part, line_content: str) -> bool:
        """Check if the value being assigned to a variable is properly quoted."""
        # Find the assignment in the line (look for VAR=VALUE pattern)
        var_name = var.name.split('.')[-1]  # Handle local variables with function prefixes
        assignment_pattern = f"{var_name}="
        
        assignment_start = line_content.find(assignment_pattern)
        if assignment_start == -1:
            return True  # Can't find assignment, assume it's safe
            
        value_start = assignment_start + len(assignment_pattern)
        
        # Look for the variable expansion in the value part
        variable_name = getattr(sensitive_part, 'variable', '')
        if not variable_name:
            return True
            
        # Find the variable expansion in the value
        var_expansion_patterns = [f'${variable_name}', f'${{{variable_name}}}']
        
        for pattern in var_expansion_patterns:
            var_pos = line_content.find(pattern, value_start)
            if var_pos != -1:
                # Check if this variable expansion is quoted
                return self._is_position_quoted(line_content, var_pos, len(pattern))
        
        return True  # Default to safe if we can't find the pattern
    
    def _is_position_quoted(self, line: str, start_pos: int, length: int) -> bool:
        """Check if a position in the line is properly quoted."""
        end_pos = start_pos + length
        
        # Check for double quotes
        if self._is_position_quoted_with(line, start_pos, end_pos, '"'):
            return True
            
        # Check for single quotes  
        if self._is_position_quoted_with(line, start_pos, end_pos, "'"):
            return True
            
        return False
    
    def _is_position_quoted_with(self, line: str, start_pos: int, end_pos: int, quote: str) -> bool:
        """Check if a position is quoted with a specific quote character."""
        # Look for opening quote before the position
        opening_quote_pos = -1
        for i in range(start_pos - 1, -1, -1):
            if line[i] == quote:
                # Check if this quote is escaped
                if i > 0 and line[i-1] == '\\':
                    continue
                opening_quote_pos = i
                break
        
        # Look for closing quote after the position
        closing_quote_pos = -1
        for i in range(end_pos, len(line)):
            if line[i] == quote:
                # Check if this quote is escaped
                if i > 0 and line[i-1] == '\\':
                    continue
                closing_quote_pos = i
                break
        
        # Both quotes must be found and the position must be between them
        return opening_quote_pos != -1 and closing_quote_pos != -1

    # for possible future use
    def _is_properly_single_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, "'")

    # for possible future use
    def _is_properly_double_quoted(self, var: 'UsedVariable') -> bool:
        return self.__is_properly_quoted(var, '"')
    
    def _is_properly_quoted(self, var: 'UsedVariable') -> bool:
        return self._is_properly_double_quoted(var) or self._is_properly_single_quoted(var)
    
    def _is_command_execution(self, var: 'UsedVariable') -> bool:
        """Check if a variable is being used as a command (at start of line) rather than as an argument."""
        if var.line >= len(self.lines):
            return False
            
        line = self.lines[var.line].strip()
        var_name = var.name
        
        # Check if the variable appears at the start of the line (possibly after whitespace)
        # This indicates it's being used as a command execution
        return line.startswith(var_name)
    
    def __is_properly_quoted(self, var: 'UsedVariable', quote: str) -> bool:
        """Check if a variable is properly quoted in its usage."""
        line = self.lines[var.line]
        var_name = var.name
        
        # Find the variable in the line
        start = var.column
        end = start + len(var_name)
        
        # Look for the nearest opening quote before the variable
        opening_quote_pos = -1
        for i in range(start - 1, -1, -1):
            if line[i] == quote:
                opening_quote_pos = i
                break
            elif line[i] == quote and quote == '"':  # Handle escaped quotes
                continue
        
        # Look for the nearest closing quote after the variable
        closing_quote_pos = -1
        for i in range(end, len(line)):
            if line[i] == quote:
                closing_quote_pos = i
                break
            elif line[i] == quote and quote == '"':  # Handle escaped quotes
                continue
        
        # Check if both quotes are found and the variable is between them
        if opening_quote_pos != -1 and closing_quote_pos != -1:
            return True
        
        return False