import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType

def test_variable_assignment_context():
    """
    Test variable assignment in command context.
    
    FOO=hello bash -c 'echo "$FOO"' should NOT be vulnerable because
    FOO is set to "hello" in that command's context, not user input.
    """
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_variable_assignment_context.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()
    
    
    # Should only detect the user input vulnerability (FOO=$1), not the command context one
    assert len(vulnerabilities) == 0, f"Found unexpected vulnerabilities: {[str(v) for v in vulnerabilities]}"

if __name__ == "__main__":
    test_variable_assignment_context() 