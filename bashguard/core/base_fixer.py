"""
Base analyzer class that defines the interface for all analyzers.
"""

from abc import ABC, abstractmethod

from bashguard.core import Vulnerability


class BaseFixer(ABC):
    """
    Abstract base class for all fixers.
    
    Each fixer should implement the fix method to fix
    specific types of vulnerabilities in Bash scripts.
    """
    
    def __init__(self):
        """
        Initialize the fixer.
        """
        pass
    
    @abstractmethod
    def fix(self, vulnerability: Vulnerability, line_content: str, original_line_content: str, base_column: int) -> tuple[str, int]:
        """
        Fix the vulnerability.
        
        Returns:
            Fixed line and number of characters added
        """
        pass 