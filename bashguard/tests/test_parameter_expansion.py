import os

from pathlib import Path

from bashguard.analyzers.parameter_expansion import ParameterExpansionAnalyzer
from bashguard.core.vulnerability import VulnerabilityType

def test_0th_parameter_expansion():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_parameter_expansion.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    analyzer = ParameterExpansionAnalyzer(Path(test_file_path), content)
    res = analyzer.analyze()[0]

    assert res.vulnerability_type == VulnerabilityType.PARAMETER_EXPANSION

    print(res.description.value)

test_0th_parameter_expansion()