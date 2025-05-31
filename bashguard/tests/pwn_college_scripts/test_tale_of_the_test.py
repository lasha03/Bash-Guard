import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_tale_of_the_test():
    
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_tale_of_the_test.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 3
    assert vulnerabilities[0].description == Description.MISSING_PATH
    assert vulnerabilities[1].description == Description.COMMAND_INJECTION 
    assert vulnerabilities[2].description == Description.COMMAND_INJECTION

test_tale_of_the_test()