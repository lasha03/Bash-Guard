"""
Analyzer for variable expansion vulnerabilities.
"""

from pathlib import Path
from typing import List, Tuple

from bashguard.core import BaseAnalyzer, Vulnerability, VulnerabilityType, SeverityLevel, Description, TSParser
from bashguard.core.logger import Logger
from bashguard.core.types import Command

class ParameterExpansionAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects issues with parameter expansion in shell scripts.
    
    It looks for potential vulnerabilities related to:
    - Expanding 0-th parameter
    """
    
    def __init__(self, script_path: Path, content: str, parser: TSParser):
        """
        Initialize the parameter expansion analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
        """
        super().__init__(script_path, content, parser)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for variable expansion vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """

        commands = self.parser.get_commands()

        vulnerabilities = []
        
        vulnerabilities.extend(self.__0th_parameter_expansion(commands))
        
        return vulnerabilities 
    
    def __0th_parameter_expansion(self, commands: List[Command]) -> List[Vulnerability]:

        vulnerabilities = []

        for command in commands:
            if command.name == '0':
                # Logger.d(str(command))
                vulnerability = Vulnerability(
                    vulnerability_type=VulnerabilityType.PARAMETER_EXPANSION,
                    severity=SeverityLevel.MEDIUM,
                    description=Description.PARAMETER_EXPANSION_0.value,

                    file_path=self.script_path,
                    line_number=command.line,
                    column=command.column,
                    line_content=None,
                )

                vulnerabilities.append(vulnerability)
        
        return vulnerabilities