import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_the_surprising_swap():
    
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_the_surprising_swap.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0].description == Description.MISSING_PATH.value 
    assert vulnerabilities[1].description == Description.PARAMETER_EXPANSION_0.value
    

test_the_surprising_swap()