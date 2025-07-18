import os
from bashguard.core import VulnerabilityType
from bashguard.core import TSParser
from pathlib import Path
from bashguard.core.vulnerability import Description
from bashguard.analyzers import CommandInjectionAnalyzer

def test_superweapon():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_superweapon.sh')
    with open(test_file_path, 'r') as f:
        content = f.read()
    
    parser = TSParser(bytes(content, 'utf-8'))
    analyzer = CommandInjectionAnalyzer(test_file_path, content, parser)
    vulnerabilities = analyzer.analyze()

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0].description == Description.COMMAND_INJECTION.value
    assert vulnerabilities[1].description == Description.COMMAND_INJECTION.value


if __name__ == "__main__":
    test_superweapon()
