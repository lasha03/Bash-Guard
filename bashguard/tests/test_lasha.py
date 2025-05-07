import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType
from bashguard.analyzers.command_injection import CommandInjectionAnalyzer
from bashguard.core import TSParser
from pathlib import Path


def test_command_injection():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_lasha.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = CommandInjectionAnalyzer(Path(test_file_path), content, parser)
    vulnerabilities = analyzer.analyze()

    assert len(vulnerabilities) == 0

    # print(vulnerabilities)
    for vulnerability in vulnerabilities:
        print(vulnerability.vulnerability_type)
        print(vulnerability.line_number, vulnerability.column)
        print(vulnerability.description.value)

test_command_injection() 