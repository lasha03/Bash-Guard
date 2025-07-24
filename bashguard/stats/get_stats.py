import os
from bashguard.analyzers import ScriptAnalyzer
from dataclasses import dataclass
from bashguard.fixers.fixer import Fixer

@dataclass
class Stats:
    stats = {'total': []}
    
    def record_stats(self, vulnerabilities):
        for v in vulnerabilities:
            if v.severity not in self.stats:
                self.stats[v.severity] = []
            self.stats[v.severity].append(v)
            self.stats['total'].append(v)

    def record(self, vulnerability):
        if vulnerability.severity not in self.stats:
            self.stats[vulnerability.severity] = []
        self.stats[vulnerability.severity].append(vulnerability)
        self.stats['total'].append(vulnerability)

    def get_stats(self):
        return self.stats


@dataclass
class ScriptAnalysisResult:
    name: str
    vulnerabilities_before_fixing: Stats
    vulnerabilities_after_fixing: Stats


class Report:
    def __init__(self, scripts):
        self.scripts = scripts
        self.total_before_fixing = Stats()
        self.total_after_fixing = Stats()

    def generate_report(self):
        for script in self.scripts:
            print(script.name)
            print("before fixing:")
            if script.vulnerabilities_before_fixing is None:
                print("Failed to analyze before fixing")
                continue
            stats = script.vulnerabilities_before_fixing.get_stats()
            for k, v in stats.items():
                self.total_before_fixing.record(v)
                print(f"{k}: {len(v)}")
            print('--------------------------------')
            print("after fixing:")
            if script.vulnerabilities_after_fixing is None:
                print("Failed to analyze after fixing")
                continue
            stats = script.vulnerabilities_after_fixing.get_stats()
            for k, v in stats.items():
                self.total_after_fixing.record(v)
                print(f"{k}: {len(v)}")
            print('--------------------------------')

    def get_total_before_fixing(self):
        return self.total_before_fixing
    
    def get_total_after_fixing(self):
        return self.total_after_fixing

def analyze_script(script_path):
    try:   
        analyzer = ScriptAnalyzer(script_path)
        vulnerabilities = analyzer.analyze()
        return Stats().record_stats(vulnerabilities), vulnerabilities
    except Exception as e:
        print(e)
        print(f"Failed to analyze {script_path}")
        return None, None


def fix_script(script_path, vulnerabilities):
    fixer = Fixer(script_path, output_path=script_path.replace(".sh", "_fixed.sh"))
    try:
        fixer.fix(vulnerabilities)
    except Exception as e:
        print(e)
        print(f"Failed to fix {script_path}")
    return script_path.replace(".sh", "_fixed.sh")


def record_script_analysis(script_path, list_of_scripts):
    vulnerabilities_stats, vulnerabilities = analyze_script(script_path)
    fixed_script_path = fix_script(script_path, vulnerabilities)
    vulnerabilities_fixed_stats, _ = analyze_script(fixed_script_path)
    list_of_scripts.append(ScriptAnalysisResult(script_path, vulnerabilities_stats, vulnerabilities_fixed_stats))

with open("/home/lasha/bashguard/bash_test_dataset/secure.list", "r") as f:
    secure_list = f.readlines()

with open("/home/lasha/bashguard/bash_test_dataset/vulnerable.list", "r") as f:
    vulnerable_list = f.readlines()

secure_scripts = []
vulnerable_scripts = []

for i, secure_script in enumerate(secure_list):
    record_script_analysis(secure_script.strip(), secure_scripts)

for vulnerable_script in vulnerable_list:
    record_script_analysis(vulnerable_script.strip(), vulnerable_scripts)

print("secure scripts:")
report = Report(secure_scripts)
report.generate_report()

print("vulnerable scripts:")
report = Report(vulnerable_scripts)
report.generate_report()


print("total before fixing:")
print(report.get_total_before_fixing())
print("total after fixing:")
print(report.get_total_after_fixing())