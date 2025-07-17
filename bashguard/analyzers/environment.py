"""
Analyzer for path related vulnerabilities.
"""

from pathlib import Path
from typing import List

from bashguard.core import BaseAnalyzer, Vulnerability, VulnerabilityType, SeverityLevel, Description, TSParser
from bashguard.core.types import AssignedVariable

class EnvironmentAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects if PATH variable is missing in a shell script.
    """
    
    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        """
        Initialize the PATH related analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, parser, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for PATH related vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """

        variables = self.parser.get_variables()
        
        vulnerabilities = []

        if not self.__path_declared(variables):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.ENVIRONMENT,
                severity=SeverityLevel.MEDIUM,
                description=Description.MISSING_PATH.value,

                file_path=self.script_path,
                line_number=-1,
                column=None,
                line_content=None,
            )
            vulnerabilities.append(vulnerability)

        return vulnerabilities
    
    
    def __path_declared(self, variables: list[AssignedVariable]) -> bool:
        for var in variables:
            if var.name == "PATH":
                return True
        
        return False