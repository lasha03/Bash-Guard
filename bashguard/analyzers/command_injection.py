import subprocess

from pathlib import Path
from typing import List, Set

from bashguard.core import (
    BaseAnalyzer, 
    TSParser, 
    Vulnerability, 
    VulnerabilityType, 
    SeverityLevel, 
    Description, 
    Recommendation, 
    Command
)

class CommandInjectionAnalyzer(BaseAnalyzer):
    """
    Analyzer for Command Injection vulnerabilities.
    Detects potential command injection vulnerabilities in bash scripts by checking for:
    - Unquoted variables in command execution
    - Command substitution with unvalidated input
    - eval/source commands with unvalidated input
    - Direct command execution with user input
    """

    def __init__(self, script_path: Path | None, content: str, parser: TSParser):
        super().__init__(script_path, content, parser)
        self.user_input_vars: Set[str] = set()  # Set of variables that come from user input


    def analyze(self) -> List[Vulnerability]:
        # Get all variables used in the script
        commands = self.parser.get_commands()
        # find user-inputted variables
        self.user_input_vars = self.parser.get_tainted_variables()
        self.assigned_vars = self.parser.get_variables()
        
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
        # print(vulnerabilities)
        
        vulnerabilities.extend(self._check_array_index_attacks())

        vulnerabilities.extend(self._check_superweapon_attack())

        # Disabled: Variable assignments are not command injection by themselves
        vulnerabilities.extend(self._check_declared_pairs())
        
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
                    description=Description.COMMAND_INJECTION.value,
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
        
        for var in injectable_variables:
            var_name = var.name
            if var_name in self.user_input_vars:
                
                test_conditions = self._extract_test_condition(self.lines[var.line], var.test_command, var.name)
                if not self.run_superweapon_attack(test_conditions, var.name):
                    continue

                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description=Description.COMMAND_INJECTION.value,
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
                        description=Description.ARRAY_INDEX_ATTACK.value,
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
        if self._is_cmd_ctx(command, command_name):
                command_name = f"{command_name}_cmd_ctx_{command.line}"

        is_variable_command = (original_name.startswith('$') or 
                             command_name in self.user_input_vars or
                             # Check if this is a variable name (not a standard command) AND it's tainted
                             (command_name.isalpha() and command_name.isupper() and command_name in self.user_input_vars))
        
        command_name = self.strip_quotes_and_dollar(command.name)
        if is_variable_command:
            # Get the line content to verify this is a real command injection
            line_content = self.lines[command.line] if command.line < len(self.lines) else ""
            
            # Skip shebang lines and other non-command contexts
            if line_content.startswith('#!') or not line_content.strip():
                return vulnerabilities
            
            # # Skip variable assignments (e.g., foo="$1")
            # if f'{command_name}=' in line_content:
            #     return vulnerabilities
            
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
                description=Description.COMMAND_INJECTION.value,
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
        
        arg = self.strip_quotes_and_dollar(cmd.arguments[0])
            
        # print(command_name, arg, arg in self.user_input_vars)
        
        if self._is_cmd_ctx(cmd, arg):
            arg = f"{arg}_cmd_ctx_{cmd.line}"
        if command_name in ['eval', 'source'] and arg in self.user_input_vars:
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                severity=SeverityLevel.CRITICAL,
                description=Description.EVAL_SOURCE.value,
                file_path=self.script_path,
                line_number=cmd.line,
                column=cmd.column,
                line_content=self.lines[cmd.line],
                recommendation=Recommendation.EVAL_SOURCE
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def _is_cmd_ctx(self, command: Command, arg: str) -> bool:
        for var in self.assigned_vars:
            if arg == var.name and var.is_in_command_context and var.line == command.line:
                return True
        return False

    # remove '$' and quotes from the command name
    @staticmethod
    def strip_quotes_and_dollar(s: str) -> str:
        return s.strip('"\'').lstrip('$')

    def _extract_test_condition(self, line_content: str, test_command: str, var_name: str) -> str:
        line = line_content.strip()

        start_pos = line.find(test_command)
        if start_pos == -1:
            return line
        
        matching_bracket = ""
        if test_command == '[':
            matching_bracket = ']'
        elif test_command == '[[':
            matching_bracket = ']]'
        elif test_command == '((':
            matching_bracket = '))'

        end_pos = line.rfind(matching_bracket)
        test_condition = line[start_pos:end_pos + len(matching_bracket)]
        conditions = test_condition.replace(test_command, "").replace(matching_bracket, "").split("&&")
        
        conditions_to_keep = []
        for condition in conditions:
            if f"${var_name}" in condition:
                conditions_to_keep.append(f"{test_command} {condition} {matching_bracket}")
            elif var_name in condition:
                conditions_to_keep.append(f"{test_command} {condition} {matching_bracket}")

        return conditions_to_keep

    def run_superweapon_attack(self, test_conditions: List[str], var_name: str) -> bool:
        for test_condition in test_conditions:
            test_condition = test_condition.replace(var_name, "var")
            var_name = "var"
            
            script = f"""
            WORKDIR=$(mktemp -d) || exit 1
            echo "pwned.pwned.pwned" > $WORKDIR/flag
            {var_name}="a[\\$(<$WORKDIR/flag)]"
            if {test_condition} ; then
                echo "{var_name}"
            else
                echo "{var_name}"
            fi
            """

            result = subprocess.run(["bash", "-c", script], 
                                capture_output=True, 
                                text=True)
            
            out = result.stdout.strip()
            if "pwned" in out:
                return True
            out = result.stderr.strip()
            if "pwned" in out:
                return True
        return False