"""
Base analyzer class that defines the interface for all analyzers.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from bashguard.core import Vulnerability, TSParser


class BaseAnalyzer(ABC):
    """
    Abstract base class for all analyzers.
    
    Each analyzer should implement the analyze method to detect
    specific types of vulnerabilities in Bash scripts.
    """
    
    def __init__(self, script_path: Path | None, content: str, parser: TSParser):
        """
        Initialize the analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
        """
        self.script_path = script_path
        self.content = content
        self.parser = parser
        self.lines = content.splitlines()
    
    @abstractmethod
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """
        pass 