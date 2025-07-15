import os
from bashguard.analyzers import VariableExpansionAnalyzer
from bashguard.core import TSParser
from pathlib import Path
from bashguard.core import VulnerabilityType

def test_variable_assginemnt_in_command_context_vuln():
    """Test that variable assignment in command context is properly handled"""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_assignemnt_in_command_context_vuln.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = VariableExpansionAnalyzer(Path(test_file_path), content, parser)
    vulnerabilities = analyzer.analyze()
    
    assert(len(vulnerabilities) == 1)
    assert(vulnerabilities[0].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION)

if __name__ == "__main__":
    test_variable_assginemnt_in_command_context_vuln()
