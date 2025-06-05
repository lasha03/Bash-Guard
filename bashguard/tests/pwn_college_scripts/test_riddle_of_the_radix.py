import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType


def test_riddle_of_the_radix():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_riddle_of_the_radix.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION
    assert vulnerabilities[1].vulnerability_type == VulnerabilityType.COMMAND_INJECTION

test_riddle_of_the_radix()