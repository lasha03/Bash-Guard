"""
Parser for content analysis, based on bashlex parser.
"""

from typing import List
import bashlex # type: ignore

class Parser:
    """
    """
    
    def __init__(self, content: str):
        """
        Initialize the parser.
        
        Args:
            content: Content to analyze
        """
        self.content = content
        self.assignment_nodes = []

    def parse(self):
        """Parse content using bashlex and divide according to keywords"""
        self.parts = bashlex.parse(self.content)
        
        for node in self.parts:
            self.__divide(node)

        
    def __divide(self, node: bashlex.ast.node):
        
        if hasattr(node, 'parts') == False or len(node.parts) == 0:
            if node.kind == 'assignment':
                self.assignment_nodes.append(node)
            return

        for child_node in node.parts:
            self.__divide(child_node)


    def get_variables(self) -> List[bashlex.ast.node]:
        return self.assignment_nodes
        