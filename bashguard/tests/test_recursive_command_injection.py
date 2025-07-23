import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType

def test_recursive_command_injection():
    """Test that command injection in nested commands is detected"""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_recursive_command_injection.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()
    
    # Filter for command injection vulnerabilities
    cmd_injection_vulnerabilities = [v for v in vulnerabilities 
                                   if v.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
    
    # Should detect:
    # 1. eval "$USER_INPUT" - direct eval with user input
    # 2. bash -c "$MALICIOUS" - bash execution with user input
    # 3. Inner command from bash -c parsing
    assert len(cmd_injection_vulnerabilities) == 2
    assert all(v.vulnerability_type == VulnerabilityType.COMMAND_INJECTION for v in cmd_injection_vulnerabilities)

if __name__ == "__main__":
    test_recursive_command_injection() 