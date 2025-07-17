import os

from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import Description


def test_index_of_insanity():

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_index_of_insanity.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    
    vulnerabilities = analyzer.analyze()
    for vuln in vulnerabilities:
        print(vuln)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].description == Description.ARRAY_INDEX_ATTACK.value 
    

test_index_of_insanity()