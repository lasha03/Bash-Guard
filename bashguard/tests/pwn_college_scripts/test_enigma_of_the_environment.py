import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_enigma_of_the_environment():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_enigma_of_the_environment.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 3
    assert vulnerabilities[0].description == Description.VARIABLE_EXPANSION.value
    assert vulnerabilities[1].description == Description.VARIABLE_EXPANSION.value
    assert vulnerabilities[2].description == Description.COMMAND_INJECTION.value

test_enigma_of_the_environment()