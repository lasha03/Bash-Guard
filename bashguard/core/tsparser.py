"""
Parser for content analysis, based on bashlex parser.
"""

from operator import index
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser, Node

class TSParser:
    
    def __init__(self, content: bytes):
        """
        Initialize the Tree-Sitter Bash parser and parse the given content.
        
        Args:
            content: Content to analyze
        """
        self.content: bytes = content

        # (variable, value)
        self.variable_assignments: list[tuple[str, str]] = []
        self.used_variables: list[str] = []

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

                self.variable_assignments.append((var, val))
            elif 'expansion' in node.type:
                par = node.text.decode()
                self.used_variables.append(par)

            for child in node.children:
                toname(child, indent + 1)
        
        toname(tree.root_node)

    def get_variables(self):
        return self.variable_assignments

    def get_used_variables(self):
        return self.used_variables
