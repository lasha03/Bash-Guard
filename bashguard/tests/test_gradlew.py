import os
from bashguard.core import VulnerabilityType
from bashguard.core import TSParser
from pathlib import Path
from bashguard.analyzers import ScriptAnalyzer

def test_gradlew():
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_gradlew.sh')

    analyzer = ScriptAnalyzer(test_file_path)
    vulnerabilities = analyzer.analyze()

    for vuln in vulnerabilities:
        print(vuln)

if __name__ == "__main__":
    test_gradlew()
