import os
from bashguard.analyzers import ScriptAnalyzer
from bashguard.core import VulnerabilityType

def test_recursive_variable_expansion():
    """Test that unquoted variables in nested commands are detected"""
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_recursive_variable_expansion.sh')
    
    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()
    
    # Should detect:
    # 1. Unquoted $FOO in 'bash -c echo $FOO'
    # 2. Unquoted $BAR in 'eval echo $BAR'
    assert len(vulnerabilities) == 2
    assert all(v.vulnerability_type == VulnerabilityType.VARIABLE_EXPANSION for v in vulnerabilities)

if __name__ == "__main__":
    test_recursive_variable_expansion() 