import os

from pathlib import Path

from bashguard.analyzers import ParameterExpansionAnalyzer
from bashguard.core import VulnerabilityType, TSParser

def test_0th_parameter_expansion():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_parameter_expansion.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = ParameterExpansionAnalyzer(Path(test_file_path), content, parser)
    res = analyzer.analyze()[0]

    assert res.vulnerability_type == VulnerabilityType.PARAMETER_EXPANSION
    assert res.line_number == 5


test_0th_parameter_expansion()