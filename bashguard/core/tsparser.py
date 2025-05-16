"""
Parser for content analysis, based on bashlex parser.
"""

import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser, Node

from bashguard.core.types import AssignedVariable, UsedVariable, Command, Subscript, Value, ValueParameterExpansion, ValuePlainVariable, SensitiveValueUnionType, ValueUserInput


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
        self.subscripts: list[Subscript] = [] # node.type == "subscript" for nodes containing array indexings

        ts_language = Language(tsbash.language())
        self.parser = Parser(ts_language)

        self._parse(self.content)
        
        self.parser.reset()
        tree = self.parser.parse(content)
        self.tainted_variables = set()
        self.function_definitions = {}
        
        self._find_tainted_variables(tree.root_node, self.tainted_variables, "", set())
    
    def _find_tainted_variables(self, node: Node, tainted_variables: set[str], parent_function_name: str, all_variables: set[str]):
        """ 
        Finds all the variables that might be influenced by a user.
        If a variable "var" is defined inside a function "f" then its name if "f.var". 
        """

        if node.type == "function_definition":
            # Note: in bash if a function is defined twice the first one is discarded
            # Note: function definitions are global
            function_name = ""
            for child in node.children:
                if child.type == "word":
                    function_name = child.text.decode()
                    break
            
            assert function_name != ""

            # add function_name and matching node to dict
            self.function_definitions[function_name] = node
            return
        
        if node.type == "command":
            # TODO read command handling

            # check if a command is calling some function and if so, jump to the matching node
            for child in node.children:
                if child.type == "command_name":
                    command_name = child.children[0].text.decode()
                    if command_name in self.function_definitions:
                        # Jump to parts of the function definition node. 
                        # Directly jumping to function definition node will return, because of check.
                        for part in self.function_definitions[command_name].children:
                            self._find_tainted_variables(part, tainted_variables, command_name, all_variables)
                else:
                    self._find_tainted_variables(child, tainted_variables, parent_function_name, all_variables)
            
            return

        local_variables = set()

        if node.type == "declaration_command" and node.children[0].type == "local":
            # handle variables declared locally in a function 
            for child in node.children:
                if child.type == "variable_assignment":
                    var_val = child.text.decode().split('=', maxsplit=1)
                    # since the variable is declared locally its prefix is parent_function_name
                    variable_name = parent_function_name + '.' + var_val[0]
                    variable_value = self.parse_value_node(child.children[-1])

                    self._check_tainted(variable_name, variable_value, tainted_variables)

                    local_variables.add(variable_name)
                    all_variables.add(variable_name)

                elif child.type == "variable_name":
                    # variable is declared for later use
                    var_val = node.text.decode()
                    variable_name = parent_function_name + '.' + var_val[0]

                    local_variables.add(variable_name)
                    all_variables.add(variable_name)

        elif node.type == "variable_assignment":
            var_val = node.text.decode().split('=', maxsplit=1)
            variable_name = self._get_real_name_of_variable(var_val[0], all_variables)
            variable_value = self.parse_value_node(node.children[-1])

            # TODO
            # variable = AssignedVariable(
            #     name=variable_name, 
            #     value=variable_value, 
            #     line=node.start_point[0], 
            #     column=node.start_point[1],
            # )

            self._check_tainted(variable_name, variable_value, tainted_variables)

        elif node.type == 'if_statement' or node.type == 'case_statement':
            # Variable is tainted if it becomes tainted in any branch of if or case statement 
            for child in node.children:
                tainted_variables |= self._find_tainted_variables(child, tainted_variables.copy(), parent_function_name, all_variables)
        else:
            for child in node.children:
                self._find_tainted_variables(child, tainted_variables, parent_function_name, all_variables)

        for variable in local_variables:
            all_variables.remove(variable)

        return tainted_variables

    def _get_real_name_of_variable(self, variable_name, all_variables):
        """
        Determine if a variable is local or global
        Iterate over all variables and find a variable with the same name which was declared the latest(has the most '.' in its name).
        """
        real_name = ""
        mx = 0
        for other_variable_name in all_variables:
            name = other_variable_name.split('.')[-1]
            cnt = other_variable_name.count('.')
            if name == variable_name and mx < cnt:
                mx = cnt
                real_name = other_variable_name
        
        # global variable which is not yet declared
        if real_name == "":
            real_name = variable_name
            all_variables.add(real_name) 

        return real_name

    def _check_tainted(self, variable_name: str, variable_value: Value, tainted_variables: set[str]):
        is_safe = True
        for sensitive_part in variable_value.sensitive_parts:
            if self._is_direct_user_input(sensitive_part) or self._contains_user_input_var(sensitive_part, tainted_variables):
                is_safe = False
                break

        if is_safe:
            tainted_variables.discard(variable_name)
        else:
            tainted_variables.add(variable_name)
    
    def _is_direct_user_input(self, value: SensitiveValueUnionType) -> bool:
        """
        Check if a value comes directly from user input.

        Checks:

            1. If value contains user-inputted variable, like "$1", "$_", "$@" etc.
            2. If value contains user-controlled environment variable, like "USER", "HOME", "PATH", "SHELL", "TERM", "DISPLAY" etc.
        """

        ref_variable: str = ""
        if isinstance(value, ValueUserInput):
            """Value received from user input, like in read command."""
            return True
        elif isinstance(value, ValueParameterExpansion):
            ref_variable = value.variable
        elif isinstance(value, ValuePlainVariable):
            ref_variable = value.variable
        
        # Check for command line arguments
        if (ref_variable in list(map(str, range(10)))) or (ref_variable in ("@", "*")):
            return True
        
        # Check for environment variables that might contain user input
        user_env_vars = ['USER', 'HOME', 'PATH', 'SHELL', 'TERM', 'DISPLAY']
        if ref_variable in user_env_vars:
            return True

        return False
    
    def _contains_user_input_var(self, value: SensitiveValueUnionType, tainted_variables: set[str]) -> bool:
        """
        Check if a value contains any variable that might be user-controlled.
        """
        # Extract all variables from the value
        vars_in_value = set()
        if isinstance(value, ValueParameterExpansion):
            vars_in_value.add(value.variable)
        elif isinstance(value, ValuePlainVariable):
            vars_in_value.add(value.variable)
        elif isinstance(value, ValueUserInput):
            return True

        return any(var in tainted_variables for var in vars_in_value)

    def _parse(self, content):
        self.parser.reset()
        tree = self.parser.parse(content)

        def toname(node: Node, indent=0):
            # print(f'NODE: {node.text.decode()}')
            # print("    " * indent + f"{node.type}: {node.text.decode()}")

            if node.type == "variable_assignment":
                var_val = node.text.decode().split('=')
                var = var_val[0]

                # children = [var, =, val]
                val = self.parse_value_node(node.children[-1])

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
                                value=Value(
                                    content="", # we do not have expression here
                                    sensitive_parts=[ValueUserInput()]
                                ),
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
                                        value=Value(
                                            content="", # we do not have expression here
                                            sensitive_parts=[ValueUserInput()]
                                        ),
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
                            line=node.start_point[0]+1,
                            column=node.start_point[1]+1,
                        )
                    )
            
            # array subscripts
            elif node.type == "subscript":
                subscript = node.text.decode()

                opening_bracket_index = subscript.find('[')
                array_name, index_expression = subscript[:opening_bracket_index], subscript[opening_bracket_index+1:-1]
                self.subscripts.append(
                    Subscript(
                        array_name=array_name,
                        index_expression=index_expression,
                        line=node.start_point[0]+1,
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
    
    def parse_parameter_expansion_node(self, value_node: Node) -> ValueParameterExpansion:
        """
        Parse a parameter expansion node.

        Retrieves:
            - Value as string
            - Prefix, like '!' in "${!var}"
            - Used variable name
        """
        def toname(node: Node) -> str | None:
            if node.type in ("subscript", "variable_name"):
                return node.text.decode()

            for child in node.children:
                result = toname(child)
                if result:
                    return result
            
            return None

        inner_variable = toname(value_node)

        # now deduce prefix
        node_text = value_node.text.decode()
        prefix = node_text[node_text.find('{')+1:node_text.find(inner_variable)]
        
        return ValueParameterExpansion(
            content=value_node.text.decode(),
            prefix=prefix,
            variable=inner_variable
        )
    
    def parse_value_node(self, value_node: Node) -> SensitiveValueUnionType:
        """
        Parse a value node and return a Value object.

        Parses:
            - Parameter expansion: "${!var}"
            - Plain variable: "$var"
            - Simple expansion: "$()"
        """

        def toname(node: Node, sensitive_parts: list[SensitiveValueUnionType] = [], depth: int = 0) -> list[SensitiveValueUnionType]:
            if node.type == "expansion": # parameter expansion
                value_parameter_expansion = self.parse_parameter_expansion_node(node)
                value_parameter_expansion.column_frame = (node.start_point[1]+1, node.end_point[1])
                sensitive_parts.append(value_parameter_expansion)

            elif node.type == "simple_expansion": # plain variable
                value_plain_variable = ValuePlainVariable(
                    variable=node.text.decode().strip('$'),
                    column_frame=(node.start_point[1]+1, node.end_point[1])
                )
                sensitive_parts.append(value_plain_variable)
            else:
                # TODO: maybe handle command substitution, backticks and others here
                # String literals are just string literals, without any sensitive parts
                pass
            
            for child in node.children:
                toname(child, sensitive_parts, depth+1)

        sensitive_parts = []
        toname(value_node, sensitive_parts)

        return Value(
            content=value_node.text.decode(),
            sensitive_parts=sensitive_parts
        )
    

    def get_variables(self):
        return self.variable_assignments

    def get_used_variables(self):
        return self.used_variables

    def get_commands(self):
        return self.commands

    def get_subscripts(self):
        return self.subscripts
    
    def get_tainted_variables(self):
        return self.tainted_variables
