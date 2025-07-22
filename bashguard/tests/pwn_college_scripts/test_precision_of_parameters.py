import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType


def test_precision_of_parameters():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_precision_of_parameters.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 5
    assert vulnerabilities[0].vulnerability_type == VulnerabilityType.UNQUOTED_COMMAND_SUBSTITUTION
    assert vulnerabilities[1].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION
    assert vulnerabilities[2].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION
    assert vulnerabilities[3].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION
    assert vulnerabilities[4].vulnerability_type == VulnerabilityType.COMMAND_INJECTION

test_precision_of_parameters()