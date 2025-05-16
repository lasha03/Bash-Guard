import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType
from bashguard.analyzers.command_injection import CommandInjectionAnalyzer
from bashguard.core import TSParser
from pathlib import Path

def test_array_index_attack():
    """Test the array index attack vulnerability."""

    test_file_path = os.path.join(os.path.dirname(__file__), 'test_array_index_attack.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = CommandInjectionAnalyzer(Path(test_file_path), content, parser)
    vulnerabilities = analyzer.analyze()

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].vulnerability_type == VulnerabilityType.ARRAY_INDEX_ATTACK
