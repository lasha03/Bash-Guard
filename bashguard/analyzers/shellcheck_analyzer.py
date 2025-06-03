
from pathlib import Path


import subprocess
from bashguard.core import BaseAnalyzer

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

        errors = []
        
        for part in parts:
            if "(error):" in part:
                errors.append(part)

        return errors