import os
from bashguard.core import VulnerabilityType
from bashguard.core import TSParser
from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.fixers.fixer import Fixer
from bashguard.core.vulnerability import Description

def test_variable_expansion():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_variable_expansion.sh')
    test_file_path = Path(test_file_path)

    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()

    fixed_script_path = os.path.join(os.path.dirname(__file__), 'test_variable_expansion_fixed.sh')
    fixed_script_path = Path(fixed_script_path)
    
    fixer = Fixer(test_file_path, output_path=fixed_script_path)
    fixer.fix(vulnerabilities)

    analyzer = ScriptAnalyzer(fixed_script_path)
    vulnerabilities = analyzer.analyze()

    assert not any(vuln.vulnerability_type == VulnerabilityType.UNQUOTED_COMMAND_SUBSTITUTION for vuln in vulnerabilities)
    assert not any(vuln.vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION for vuln in vulnerabilities)


if __name__ == "__main__":
    test_variable_expansion()
