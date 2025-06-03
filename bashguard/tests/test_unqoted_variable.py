import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType
from bashguard.analyzers.variable_expansion import VariableExpansionAnalyzer
from bashguard.core import TSParser
from pathlib import Path

def test_unqoted_variable():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_unqoted_variable.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = VariableExpansionAnalyzer(Path(test_file_path), content, parser)
    vulnerabilities = analyzer.analyze()

    # assert len(vulnerabilities) == 1
    # assert vulnerabilities[0].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION

test_unqoted_variable()
