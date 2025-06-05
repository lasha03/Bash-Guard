import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_masquerade_of_the_self():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_masquerade_of_the_self.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].description == Description.PARAMETER_EXPANSION_0

test_masquerade_of_the_self()