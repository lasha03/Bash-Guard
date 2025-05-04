import os

from pathlib import Path

from bashguard.analyzers import EnvironmentAnalyzer
from bashguard.core import VulnerabilityType

def test_missing_path():
    
    content = ""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_missing_path.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()

    analyzer = EnvironmentAnalyzer(Path(test_file_path), content)
    res = analyzer.analyze()[0]

    assert res.vulnerability_type == VulnerabilityType.ENVIRONMENT

test_missing_path()