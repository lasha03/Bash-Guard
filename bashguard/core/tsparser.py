"""
Parser for content analysis, based on bashlex parser.
"""

import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser, Node

from bashguard.core.types import AssignedVariable, UsedVariable, InjectableVariable, Command, Subscript, Value, ValueParameterExpansion, ValuePlainVariable, SensitiveValueUnionType, ValueUserInput, ValueCommandSubtitution, DeclaredPair


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

        # self._parse(self.content)
        
        self.parser.reset()
        tree = self.parser.parse(content)
        self.tainted_variables = set()
        self.function_definitions = {}
        self.injectable_variables: list[InjectableVariable] = []
        self.declared_pairs: list[DeclaredPair] = []  # pairs of variables declared with declare, typeset and so on.

        self._find_tainted_variables(tree.root_node, self.tainted_variables, "", set())
    
    def _find_tainted_variables(self, node: Node, tainted_variables: set[str], parent_function_name: str, all_variables: set[str]):
        """ 
        Finds all the variables that might be influenced by a user.
        If a variable "var" is defined inside a function "f" then its name if "f.var". 
        """
        # print(node.type)

        # print("hereeeeee", node.type, node.text.decode())
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
            return tainted_variables
        
        # save command with its argument. If command is read save the corresopondig argument 
        # as tainted variable
        if node.type == "command":
            self._save_command(node, all_variables, tainted_variables, parent_function_name)

           
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
                elif child.type == "variable_assignment":
                    # This is an environment variable assignment for this command only
                    # Don't treat it as a global assignment - it doesn't affect the global variable
                    pass
                else:
                    self._find_tainted_variables(child, tainted_variables, parent_function_name, all_variables)
            
            return tainted_variables

        if node.type == "test_command":
            # detect variables, injectable by a superweapon, in test command [[ ]], [].
            test_command = node.children[0].type

            def rec(node, ok=False):
                if ok and node.type == 'variable_name':
                    self.injectable_variables.append(
                        InjectableVariable(
                            name=self._get_real_name_of_variable(node.text.decode(), all_variables),
                            line=node.start_point[0],
                            column=node.start_point[1],
                            test_command=test_command,
                        )
                    )
                    # print(node.text.decode())

                # Handle expansion nodes within the test command
                elif 'expansion' in node.type:
                    if '[' in node.text.decode():
                        self._save_subscript(node)
                    self._save_expansion(node)

                flags = [
                    '-a', '-b', '-c', '-d', '-e', '-f', '-g', '-G', '-h', '-k', '-L', '-N', '-o', '-O', '-p', '-r', '-s', '-S', '-t', '-u', '-v', '-w', '-x', '-z',
                    '-ef', '-ot', '-b', '-c', '-eq', '-ne', '-gt', '-lt', '-ge', '-le'
                ]

                for child in node.children:
                    if child.type == "test_operator" and child.text.decode() in flags:
                        ok = True
                
                for child in node.children:
                    rec(child, ok)
            
            rec(node)
            return tainted_variables

        if node.type == "arithmetic_expansion":
            # detect variables, injectable by a superweapon, in arithmetic expression (( )).
            test_command = node.children[0].type

            def rec(node, ok=False):
                if ok and node.type == 'variable_name':
                    self.injectable_variables.append(
                        InjectableVariable(
                            name=self._get_real_name_of_variable(node.text.decode(), all_variables),
                            line=node.start_point[0],
                            column=node.start_point[1],
                            test_command=test_command
                        )
                    )
                    # print(node.text.decode())

                for child in node.children:
                    if child.type in ["==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "=", "+=", "-=", "*=", "/="]:
                        ok = True
                
                for child in node.children:
                    rec(child, ok)
            
            rec(node)
            return tainted_variables

        local_variables = set()

        # detect things like "declare "$1"="$2"" , "typeset "$1"="$2"" and so on.
        if node.type == "declaration_command":
            for child in node.children:
                if child.type == "concatenation":
                    variables = []
                    def rec(node):
                        if node.type == "variable_name":
                            variables.append(node.text.decode())
                        for child in node.children:
                            rec(child)
                    rec(child)

                    if len(variables) == 2:
                        self.declared_pairs.append(
                            DeclaredPair(
                                var1=variables[0], 
                                var2=variables[1], 
                                line=child.start_point[0],
                                column=child.start_point[1]
                            )
                        )


        # handle variables declared locally in a function 
        if node.type == "declaration_command" and node.children[0].type == "local":
            for child in node.children:
                if child.type == "variable_assignment":
                    var_val = child.text.decode().split('=', maxsplit=1)
                    # since the variable is declared locally its prefix is parent_function_name
                    variable_name = parent_function_name + '.' + var_val[0]
                    variable_value = self.parse_value_node(child.children[-1], all_variables, tainted_variables, parent_function_name)

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
            # kitxva - es ra sachiroa
            variable_name = self._get_real_name_of_variable(var_val[0], all_variables)
            
            # Check if this is an array assignment
            if '[' in var_val[0]:
                self._save_subscript(node)
            
            variable_value = self.parse_value_node(node.children[-1], all_variables, tainted_variables, parent_function_name)

            self.variable_assignments.append(
                AssignedVariable(
                    name=variable_name, 
                    value=variable_value, 
                    line=node.start_point[0], 
                    column=node.start_point[1],
                )
            )

            self._check_tainted(variable_name, variable_value, tainted_variables)

        # TODO
        # am testebze mushaobs mara aseti casebi echo $(array4[index]), echo $array5[index]
        # ar ihendleba
        #(aset casebs shellchecki ichers turme)
        elif node.type == "subscript":
            self._save_subscript(node)

        elif 'expansion' in node.type:
            # Check if this is an array expansion
            if '[' in node.text.decode():
                self._save_subscript(node)
            self._save_expansion(node)
            
            # Check if this variable expansion is being used as a command (standalone at statement level)
            if self._is_variable_command_execution(node):
                var_name = node.text.decode().lstrip('$')
                command = Command(
                    name=var_name,
                    arguments=[],
                    line=node.start_point[0],
                    column=node.start_point[1],
                )
                self.commands.append(command)

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

    def _is_variable(self, arg: str) -> bool:
        arg = arg.strip("\"'")
        return arg.startswith("$")

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
                if variable_name == "WORKDIR":
                    print(sensitive_part)
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
            3. If value contains command substitution, which can produce unpredictable output.
        """

        ref_variable: str = ""
        if isinstance(value, ValueUserInput):
            """Value received from user input, like in read command."""
            return True
        elif isinstance(value, ValueParameterExpansion):
            ref_variable = value.variable
        elif isinstance(value, ValuePlainVariable):
            ref_variable = value.variable
        elif isinstance(value, ValueCommandSubtitution):
            return self._is_command_substitution_risky(value)
        
        # Check for command line arguments
        if (ref_variable in list(map(str, range(10)))) or (ref_variable in ("@", "*")):
            return True
        
        # Check for environment variables that might contain user input
        user_env_vars = ['USER', 'HOME', 'PATH', 'SHELL', 'TERM', 'DISPLAY']
        if ref_variable in user_env_vars:
            return True

        return False

    def _is_command_substitution_risky(self, value: ValueCommandSubtitution) -> bool:
        if not hasattr(value, "command"):
            return True

        command_name = ""
        if hasattr(value.command, "name"):
            command_name = value.command.name

        safe_commands = ['mktemp']
        if command_name in safe_commands:
            return False
        return True
    
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
        elif isinstance(value, ValueCommandSubtitution):
            return self._is_command_substitution_risky(value)

        return any(var in tainted_variables for var in vars_in_value)

    
    
    def parse_parameter_expansion_node(self, value_node: Node) -> ValueParameterExpansion:
        """
        Parse a parameter expansion node.

        Retrieves:
            - Value as string
            - Prefix, like '!' in "${!var}"
            - Used variable name
        """
        def toname(node: Node, indent = 0) -> str | None:
            # print(f'NODE: {node.text.decode()}')
            # print("    " * indent + f"{node.type}: {node.text.decode()}")

            if node.type in ("subscript", "variable_name", "special_variable_name"):
                return node.text.decode()

            for child in node.children:
                result = toname(child, indent + 1)
                if result:
                    return result
            
            return None

        # print(f'Value Node Text: {value_node.text.decode()}')
        inner_variable = toname(value_node)

        # now deduce prefix
        node_text = value_node.text.decode()
        # print(f'Inner variable: {inner_variable}')
        # print(f'NODE_TEXT: {node_text}')
        prefix = node_text[node_text.find('{')+1:node_text.find(inner_variable)]
        
        return ValueParameterExpansion(
            content=value_node.text.decode(),
            prefix=prefix,
            variable=inner_variable
        )
    
    def parse_value_node(self, value_node: Node, all_variables, tainted_variables, parent_function_name) -> SensitiveValueUnionType:
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

            elif node.type == "command":
                # handle command substitution, backticks and others here
                command = self._save_command(node, all_variables, tainted_variables, parent_function_name)
                if command:
                    value_command_substitution = ValueCommandSubtitution(command)
                    sensitive_parts.append(value_command_substitution)

            #TODO more tests needed
            elif node.type == "subscript":
                self._save_subscript(node)
            
            for child in node.children:
                toname(child, sensitive_parts, depth+1)

        sensitive_parts = []
        toname(value_node, sensitive_parts)

        return Value(
            content=value_node.text.decode(),
            sensitive_parts=sensitive_parts
        )
    

    def _save_command(self, node, all_variables, tainted_variables, parent_function_name):
        """
        Parse and save a command with its arguments using tree-sitter nodes.
        Handles both direct commands and commands stored in variables.
        """
        cmd_name = None
        cmd_args = []

        def extract_variable_name(node: Node) -> str:
            """Extract variable name from a node, removing $, quotes, etc."""
            text = node.text.decode()
            # Remove $, quotes, and any other decorations
            text = text.strip("$'\"")
            return text

        def process_argument_node(arg_node: Node):
            """Process a single argument node and extract its value."""
            # For command arguments, we want to preserve the original text
            # so that recursive parsing can work with quoted strings
            return arg_node.text.decode()

        # Find command name
        for child in node.children:
            if child.type == "command_name":
                # Command name could be a direct word or a variable
                if child.children:
                    # If command name is a variable
                    cmd_name = extract_variable_name(child.children[0])
                else:
                    # Direct command name
                    cmd_name = extract_variable_name(child)
            elif child.type in [
                "word", 
                "expansion", 
                "simple_expansion", 
                "string",
                "raw_string",
                "concatenation",
                "command_substitution",
                "arithmetic_expansion",
                "process_substitution",
                "heredoc_body",
                "redirect"
            ]:
                # Process each argument
                arg_value = process_argument_node(child)
                if arg_value:
                    cmd_args.append(arg_value)

        if cmd_name:
            # Save the command with its arguments
            cmd_name = self._get_real_name_of_variable(cmd_name, all_variables)
            command = Command(
                    name=cmd_name,
                    arguments=cmd_args,
                    line=node.start_point[0],
                    column=node.start_point[1],
                )
            self.commands.append(command)

            # Special handling for read command
            if cmd_name == "read":
                for arg in cmd_args:
                    if not arg.startswith('-'):  # Skip options
                        variable_name = self._get_real_name_of_variable(arg, all_variables)
                        self.variable_assignments.append(
                            AssignedVariable(
                                name=variable_name,
                                value=Value(
                                    content="",
                                    sensitive_parts=[ValueUserInput()]
                                ),
                                line=node.start_point[0],
                                column=node.start_point[1],
                            )
                        )
                        tainted_variables.add(variable_name)
                        
            # Recursive parsing for commands that execute other commands
            self._parse_recursive_commands(command, all_variables, tainted_variables, parent_function_name)
            
            return command
        return None

    def _parse_recursive_commands(self, command: 'Command', all_variables: set[str], tainted_variables: set[str], parent_function_name: str):
        """
        Parse commands that execute other commands (bash -c, eval, etc.)
        and recursively find variables within their string arguments.
        """
        cmd_name = command.name
        
        # Commands that execute other bash code
        recursive_commands = {'bash', 'sh', 'eval', 'source', '.'}
        
        if cmd_name not in recursive_commands:
            return
            
        # For bash -c and sh -c, parse the command string argument
        if cmd_name in ['bash', 'sh'] and len(command.arguments) >= 2 and command.arguments[0] == '-c':
            command_string = command.arguments[1]
            self._parse_command_string(command_string, command.line, all_variables, tainted_variables, parent_function_name)
            
        # For eval, source, and . commands, parse all arguments as potential command strings
        elif cmd_name in ['eval', 'source', '.']:
            for arg in command.arguments:
                self._parse_command_string(arg, command.line, all_variables, tainted_variables, parent_function_name)

    def _parse_command_string(self, command_string: str, base_line: int, all_variables: set[str], tainted_variables: set[str], parent_function_name: str):
        """
        Parse a command string to find variables and commands within it.
        """
        if not command_string:
            return
            
        try:
            # Parse the command string as bash code
            ts_language = Language(tsbash.language())
            parser = Parser(ts_language)
            
            # Remove outer quotes if present (only single or double, not both)
            clean_string = command_string
            if (clean_string.startswith("'") and clean_string.endswith("'")) or \
               (clean_string.startswith('"') and clean_string.endswith('"')):
                clean_string = clean_string[1:-1]
            tree = parser.parse(clean_string.encode())
            
            if tree.root_node:
                self._find_commands_in_node(tree.root_node, all_variables, tainted_variables, parent_function_name, base_line)
                
        except Exception as e:
            # If parsing fails, try to at least find simple variable expansions
            self._find_simple_variables_in_string(command_string, base_line)

    def _find_commands_in_node(self, node, all_variables: set[str], tainted_variables: set[str], parent_function_name: str, base_line: int):
        """
        Recursively traverse AST nodes to find commands and variables.
        """
        if node.type == "command":
            self._save_command(node, all_variables, tainted_variables, parent_function_name)
        elif 'expansion' in node.type:
            # Check if this variable is properly quoted in its immediate context
            if self._is_variable_quoted_in_context(node):
                # Skip properly quoted variables in recursive context
                pass  
            else:
                # Always add the variable for variable expansion analysis
                # The command injection analyzer will handle direct shell execution contexts
                adjusted_node_line = base_line + node.start_point[0]
                var_expansion = UsedVariable(
                    name=node.text.decode(),
                    line=adjusted_node_line,
                    column=node.start_point[1],
                )
                self.used_variables.append(var_expansion)
            
        for child in node.children:
            self._find_commands_in_node(child, all_variables, tainted_variables, parent_function_name, base_line)

    def _is_variable_quoted_in_context(self, var_node) -> bool:
        """
        Check if a variable node is properly quoted in its immediate AST context.
        """
        parent = var_node.parent
        if not parent:
            return False
            
        # Check if the variable is within a quoted string context
        while parent:
            if parent.type in ['string', 'raw_string']:
                # Check if this is a double-quoted string (which allows variable expansion but provides some protection)
                parent_text = parent.text.decode()
                if parent_text.startswith('"') and parent_text.endswith('"'):
                    return True
            parent = parent.parent
            
        return False

    def _find_simple_variables_in_string(self, command_string: str, base_line: int):
        """
        Simple regex-based variable detection as fallback.
        """
        import re
        # Find $VAR and ${VAR} patterns
        var_pattern = r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?'
        matches = re.finditer(var_pattern, command_string)
        
        for match in matches:
            var_name = '$' + match.group(1)
            var_expansion = UsedVariable(
                name=var_name,
                line=base_line,
                column=match.start(),
            )
            self.used_variables.append(var_expansion)

    def _save_subscript(self, node: Node) -> None:
        """
        Parse and save a subscript node.
        Handles array access like array[index] and array assignments.
        """
        def extract_index_expression(node: Node) -> str:
            """Extract the index expression from a subscript node."""
            if not node.children:
                return node.text.decode()
            
            # Handle nested expressions in the index
            index_parts = []
            for child in node.children:
                if child.type == "word":
                    index_parts.append(child.text.decode())
                elif child.type in ["expansion", "simple_expansion"]:
                    index_parts.append(child.text.decode())
                elif child.type == "command_substitution":
                    index_parts.append(child.text.decode())
                else:
                    index_parts.append(extract_index_expression(child))
            return "".join(index_parts)

        # Get the full text of the subscript
        subscript = node.text.decode()
        
        # Handle array assignments like array[index]=value
        if "=" in subscript:
            array_part = subscript[:subscript.find("=")].strip()
            opening_bracket_index = array_part.find('[')
            array_name = array_part[:opening_bracket_index]
            index_expression = array_part[opening_bracket_index+1:-1]
        else:
            # Handle array expansions like ${array[index]}
            if subscript.startswith("${"):
                # Remove ${ and } and then find [
                inner = subscript[2:-1]
                opening_bracket_index = inner.find('[')
                array_name = inner[:opening_bracket_index]
                index_expression = inner[opening_bracket_index+1:-1]
            else:
                opening_bracket_index = subscript.find('[')
                array_name = subscript[:opening_bracket_index]
                index_expression = subscript[opening_bracket_index+1:-1]

        self.subscripts.append(
            Subscript(
                array_name=array_name,
                index_expression=index_expression,
                line=node.start_point[0]+1,
                column=node.start_point[1],
            )
        )

    def _save_expansion(self, node: Node) -> None:
        """
        Parse and save an expansion node.
        Handles variable expansions like $var, ${var}, etc.
        """
        par = node.text.decode()
        self.used_variables.append(
            UsedVariable(
                name=par, 
                line=node.start_point[0], 
                column=node.start_point[1],
            )
        )

    def _is_variable_command_execution(self, node: Node) -> bool:
        """
        Check if a variable expansion node is being used as a command execution.
        This occurs when the variable is at the statement level (not within another command).
        """
        # Check if the parent is a statement-level context
        parent = node.parent
        if not parent:
            return False
            
        # Check if this expansion is a direct child of a command or pipeline
        # If the parent is a command, then this variable is being executed as a command
        if parent.type in ['command', 'pipeline']:
            # Check if this is the first child (command name position)
            if parent.children and parent.children[0] == node:
                return True
        
        # Check if this is a standalone statement
        # Look for patterns where the variable is the main element of a statement
        if parent.type in ['program', 'compound_statement', 'subshell', 'function_definition']:
            # This variable expansion is at statement level
            return True
            
        return False

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
    
    def get_injectable_variables(self):
        return self.injectable_variables

    def get_declared_pairs(self):
        return self.declared_pairs