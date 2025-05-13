"""
Parser for content analysis, based on bashlex parser.
"""

from operator import index
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser, Node

from bashguard.core.types import AssignedVariable, UsedVariable, Command


class TSParser:
    
    def __init__(self, content: bytes):
        """
        Initialize the Tree-Sitter Bash parser and parse the given content.
        
        Args:
            content: Content to analyze
        """
        self.content: bytes = content

        # (variable, value)
        self.variable_assignments: list[AssignedVariable] = []
        self.used_variables: list[UsedVariable] = []
        self.commands: list[Command] = []

        ts_language = Language(tsbash.language())
        self.parser = Parser(ts_language)

        self._parse(self.content)
        
        self.parser.reset()
        tree = self.parser.parse(content)
        self.tainted_variables = set()
        # self._find_function_definitions() TODO
        self._find_tainted_variables(tree.root_node, self.tainted_variables)

    
    def _find_tainted_variables(self, node, tainted_variables):
        """ Finds all the variables that might be influenced by a user """

        if node.type == "variable_assignment":
            var_val = node.text.decode().split('=')
            variable_name = var_val[0]
            variable_value = var_val[1]

            # TODO
            variable = AssignedVariable(
                name=variable_name, 
                value=variable_value, 
                line=node.start_point[0], 
                column=node.start_point[1],
            )

            if self._is_direct_user_input(variable_value) or self._contains_user_input_var(variable_value, tainted_variables):
                # If a variable is assigned to a user input directly or indirectly it is tainted  
                tainted_variables.add(variable_name)
            else:
                # Otherwise it is safe, even though it might have been tainted before
                tainted_variables.discard(variable_name)

        elif node.type == 'if_statement' or node.type == 'case_statement':
            # Variable is tainted if it becomes tainted in any branch of if or case statement 
            for child in node.children:
                tainted_variables |= self._find_tainted_variables(child, tainted_variables.copy())
        else:
            for child in node.children:
                self._find_tainted_variables(child, tainted_variables)

        return tainted_variables
    
    def get_tainted_variables(self):
        return self.tainted_variables

    def _parse(self, content):
        self.parser.reset()
        tree = self.parser.parse(content)

        def toname(node: Node, indent=0):
            # print(f'NODE: {node.text.decode()}')
            # print("    " * indent + f"{node.type}: {node.text.decode()}")

            if node.type == "variable_assignment":
                var_val = node.text.decode().split('=')
                var = var_val[0]
                val = var_val[1]

                self.variable_assignments.append(
                    AssignedVariable(
                        name=var, 
                        value=val, 
                        line=node.start_point[0], 
                        column=node.start_point[1],
                    )
                )

            elif node.type == "command":
                cmd = node.text.decode()

                # Check if the command is read command and if so save argument as user input variable
                if cmd.startswith("read"):
                    parts = cmd[len("read"):].strip().split()
                    if not parts:  # read without arguments
                        self.variable_assignments.append(
                            AssignedVariable(
                                name="REPLY",  # default variable for read without args
                                value="user input",
                                line=node.start_point[0],
                                column=node.start_point[1],
                            )
                        )
                    else:
                        # Handle read with options (-p, -s, -n, etc)
                        var_start = 0
                        for i, part in enumerate(parts):
                            if not part.startswith('-'):
                                var_start = i
                                break
                        
                        # Add all variables that read will store into
                        # cases like read var1 var2 var3
                        for var in parts[var_start:]:
                            if var:  # Skip empty strings
                                self.variable_assignments.append(
                                    AssignedVariable(
                                        name=var,
                                        value="user input",
                                        line=node.start_point[0],
                                        column=node.start_point[1],
                                    )
                                )
                                
                # save command name and arguments
                parts = cmd.split()
                if parts:
                    cmd_name = parts[0]
                    cmd_args = parts[1:]
                    self.commands.append(
                        Command(
                            name=cmd_name,
                            arguments=cmd_args,
                            line=node.start_point[0],
                            column=node.start_point[1],
                        )
                    )        

            elif 'expansion' in node.type:
                par = node.text.decode()
                self.used_variables.append(
                    UsedVariable(
                        name=par, 
                        line=node.start_point[0], 
                        column=node.start_point[1],
                    )
                )

            for child in node.children:
                toname(child, indent + 1)
        
        toname(tree.root_node)
    
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
    
    def _contains_user_input_var(self, value: str, tainted_variables) -> bool:
        """Check if a value contains any variable that comes from user input."""
        # Extract all variables from the value
        vars_in_value = set()
        parts = value.split('$')
        for part in parts[1:]:  # Skip first part as it's before any $
            var_name = ''
            for char in parts[1]:
                if char.isalnum() or char == '_':
                    var_name += char
                else:
                    break
            if var_name:
                vars_in_value.add(var_name)
        
        # Check if any of these variables are known to come from user input
        return any(var in tainted_variables for var in vars_in_value)

    def get_variables(self):
        return self.variable_assignments

    def get_used_variables(self):
        return self.used_variables

    def get_commands(self):
        return self.commands
