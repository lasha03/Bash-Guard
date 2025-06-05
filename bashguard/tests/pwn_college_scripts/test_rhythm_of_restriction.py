import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType


def test_rhythm_of_restriction():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_rhythm_of_restriction.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].vulnerability_type == VulnerabilityType.COMMAND_INJECTION

test_rhythm_of_restriction()