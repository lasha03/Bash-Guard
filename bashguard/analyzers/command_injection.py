from pathlib import Path
from typing import List
from bashguard.core import BaseAnalyzer, TSParser, Vulnerability

class CommandInjectionAnalyzer(BaseAnalyzer):
    """
    Analyzer for Command Injection vulnerabilities.
    """

    def __init__(self, script_path: Path, content: str, parser: TSParser, verbose: bool = False):
        super().__init__(script_path, content, parser, verbose)
    
    def analyze(self) -> List[Vulnerability]:
        return []