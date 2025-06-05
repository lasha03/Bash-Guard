import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_secrets_of_the_shell():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_secrets_of_the_shell.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].description == Description.COMMAND_INJECTION

test_secrets_of_the_shell()