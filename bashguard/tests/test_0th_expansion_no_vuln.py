import os

from pathlib import Path

from bashguard.analyzers import ParameterExpansionAnalyzer
from bashguard.core import TSParser

def test_0th_parameter_expansion_no_vuln():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_0th_expansion_no_vuln.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = ParameterExpansionAnalyzer(Path(test_file_path), content, parser)
    res = analyzer.analyze()

    assert len(res) == 0

test_0th_parameter_expansion_no_vuln()