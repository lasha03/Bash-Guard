from bashguard.analyzers.shellcheck_analyzer import ShellcheckAnalyzer
import os

def test_shellcheck_analyzer():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_shellcheck_analyzer.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    a = ShellcheckAnalyzer(test_file_path, content)
    print(a.analyze())
    assert len(a.analyze()) > 0

test_shellcheck_analyzer()