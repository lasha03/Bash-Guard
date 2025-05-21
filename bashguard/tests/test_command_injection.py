import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType
from bashguard.analyzers.command_injection import CommandInjectionAnalyzer
from bashguard.core import TSParser
from pathlib import Path

def test_command_injection():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_command_injection.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = CommandInjectionAnalyzer(Path(test_file_path), content, parser)
    vulnerabilities = analyzer.analyze()

    assert len(vulnerabilities) == 3
    for v in vulnerabilities:
        assert v.vulnerability_type == VulnerabilityType.COMMAND_INJECTION

test_command_injection() 