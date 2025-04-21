"""
Analyzer for path related vulnerabilities.
"""

import bashlex # type: ignore

from pathlib import Path
from typing import List

from bashguard.core.base_analyzer import BaseAnalyzer
from bashguard.core.vulnerability import Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.parser import Parser

class EnvironmentAnalyzer(BaseAnalyzer):
    """
    Analyzer that detects if PATH variable is missing in a shell script.
    """
    
    def __init__(self, script_path: Path, content: str, verbose: bool = False):
        """
        Initialize the PATH related analyzer.
        
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        """
        Analyze the script for PATH related vulnerabilities.
        
        Returns:
            List of vulnerabilities found
        """

        parser = Parser(self.content)
        parser.parse()
        variables = parser.get_variables()
        
        vulnerabilities = []

        if not self.__path_declared(variables):
            vulnerability = Vulnerability(
                vulnerability_type=VulnerabilityType.ENVIRONMENT,
                severity=SeverityLevel.MEDIUM,
                description=Description.MISSING_PATH,

                file_path=self.script_path,
                line_number=-1,
                column=None,
                line_content=None,
            )
            vulnerabilities.append(vulnerability)    

        
        return vulnerabilities 
    
    
    def __path_declared(self, variables: List[bashlex.ast.node]) -> bool:
        for variable in variables:
            word = variable.word
            if word.split('=')[0] == 'PATH':
                return True
        
        return False