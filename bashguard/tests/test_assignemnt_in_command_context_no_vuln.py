import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType

def test_variable_assginemnt_in_command_context():
    """Test that variable assignment in command context is properly handled"""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_assignemnt_in_command_context_no_vuln.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()

    # Should detect recursive command parsing but no vulnerabilities since variables are properly quoted
    assert len(vulnerabilities) == 0

if __name__ == "__main__":
    test_variable_assginemnt_in_command_context()
