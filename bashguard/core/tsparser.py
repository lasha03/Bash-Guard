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

    def get_variables(self):
        return self.variable_assignments

    def get_used_variables(self):
        return self.used_variables

    def get_commands(self):
        return self.commands
