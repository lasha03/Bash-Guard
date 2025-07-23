import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import TSParser
from pathlib import Path
from bashguard.core import VulnerabilityType

def test_variable_assginemnt_in_command_context_vuln():
    """Test that variable assignment in command context is properly handled"""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_assignemnt_in_command_context_vuln.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()
    
    for v in vulnerabilities:
        print(v)

    assert(len(vulnerabilities) == 2)
    assert(vulnerabilities[0].vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION)
    assert(vulnerabilities[1].vulnerability_type == VulnerabilityType.COMMAND_INJECTION)

if __name__ == "__main__":
    test_variable_assginemnt_in_command_context_vuln()
