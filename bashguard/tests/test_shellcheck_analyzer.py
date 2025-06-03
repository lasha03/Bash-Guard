from bashguard.analyzers.shellcheck_analyzer import ShellcheckAnalyzer, VulnerabilityType
import os

def test_shellcheck_analyzer():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_shellcheck_analyzer.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    a = ShellcheckAnalyzer(test_file_path, content)
    # print(a.analyze())
    res = a.analyze()
    assert len(res) == 1
    assert res[0].vulnerability_type == VulnerabilityType.SYNTAX_ERROR

test_shellcheck_analyzer()