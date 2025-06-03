
from pathlib import Path


import subprocess
from bashguard.core import BaseAnalyzer, Vulnerability, VulnerabilityType, SeverityLevel, Description
from bashguard.core.vulnerability import Recommendation

class ShellcheckAnalyzer(BaseAnalyzer):
    """
    Analyze script using "shellcheck" for syntax errors.
    """
    
    def __init__(self, script_path: Path, content: str, verbose: bool = False):
        """
        Args:
            script_path: Path to the script being analyzed
            content: Content of the script
            verbose: Whether to enable verbose logging
        """
        super().__init__(script_path, content, verbose)
    
    def analyze(self) -> list[str]:
        """
        Analyze the script using "shellcheck".

        Returns:
            Return errors detected by a shellcheck. 
            Ignore all the warnings.
        """

        result = subprocess.run(["shellcheck", self.script_path], capture_output=True)
        text = result.stdout.decode()

        pattern = f"In {self.script_path}"

        
        parts = []
        current_part = []

        for line in text.splitlines():
            if line.startswith("For more information"):
                break

            if line.startswith(pattern):
                if len(current_part) > 0 and current_part[0].startswith(pattern):
                    parts.append("\n".join(current_part))

                current_part = []

            current_part.append(line)

        # Add the last part if exists
        if len(current_part) > 0:
            parts.append("\n".join(current_part))

        # # Print the parts
        # for i, part in enumerate(parts, 1):
        #     print(f"--- Part {i} ---\n{part}\n")

        vulnerabilities = []
        
        for part in parts:
            
            # Extract line number
            line_number = int(part[part.find("line", len(pattern))+5:part.find(":", len(pattern))]) - 1
            
            for info in part.splitlines()[2:]:
                # Extract column 
                column = len(info) - len(info.lstrip(' '))
                
                # Check for vulnerabilities
                if "SC1072 (error):  Fix any mentioned problems and try again" in info:
                    break

                if "(error):" in info:
                    vulnerability = Vulnerability(
                        vulnerability_type=VulnerabilityType.SYNTAX_ERROR,
                        severity=SeverityLevel.LOW,
                        description=info,
                        file_path=self.script_path,
                        line_number=line_number,
                        column=column,
                        recommendation=Recommendation.SYNTAX_ERROR
                    )
                    vulnerabilities.append(vulnerability)
        
                if "SC2086 (info): Double quote to prevent globbing and word splitting." in info or \
                    "SC2060 (warning): Quote parameters to tr to prevent glob expansion." in info or \
                    "SC2053 (warning): Quote the right-hand side of = in [[ ]] to prevent glob matching." in info:
                    
                    vulnerability = Vulnerability(
                        vulnerability_type=VulnerabilityType.VARIABLE_EXPANSION,
                        severity=SeverityLevel.HIGH,
                        description=Description.VARIABLE_EXPANSION,
                        file_path=self.script_path,
                        line_number=line_number,
                        column=column,
                        recommendation=Recommendation.VARIABLE_EXPANSION
                    )
                    vulnerabilities.append(vulnerability)



        return vulnerabilities