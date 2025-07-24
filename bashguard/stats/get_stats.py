import os
from bashguard.analyzers import ScriptAnalyzer
from dataclasses import dataclass
from bashguard.fixers.fixer import Fixer


class Stats:
    def __init__(self):
        self.stats = {'total': []}
    
    def record_stats(self, vulnerabilities):
        for v in vulnerabilities:
            if v.severity not in self.stats:
                self.stats[v.severity] = []
            self.stats[v.severity].append(v)
            self.stats['total'].append(v)

    def record(self, key, value):
        if key not in self.stats:
            self.stats[key] = []
        self.stats[key].extend(value)
        self.stats['total'].extend(value)

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
                self.total_before_fixing.record(k, v)
                print(f"{k}: {len(v)}")
            print('--------------------------------')
            print("after fixing:")
            if script.vulnerabilities_after_fixing is None:
                print("Failed to analyze after fixing")
                continue
            stats = script.vulnerabilities_after_fixing.get_stats()
            for k, v in stats.items():
                self.total_after_fixing.record(k, v)
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
        stats = Stats()
        stats.record_stats(vulnerabilities)
        return stats, vulnerabilities
    except Exception as e:
        print(e)
        print(f"Failed to analyze {script_path}")
        return None, None


def fix_script(script_path, vulnerabilities):
    try:
        fixed_script_path = script_path.replace(".sh", "_fixed.sh")
        fixer = Fixer(script_path, output_path=fixed_script_path)
        fixer.fix(vulnerabilities)
    except Exception as e:
        print(e)
        print(f"Failed to fix {script_path}")
    return fixed_script_path


def record_script_analysis(script_path):
    vulnerabilities_stats, vulnerabilities = analyze_script(script_path)
    fixed_script_path = fix_script(script_path, vulnerabilities)
    vulnerabilities_fixed_stats, _ = analyze_script(fixed_script_path)
    return ScriptAnalysisResult(script_path, vulnerabilities_stats, vulnerabilities_fixed_stats)

with open("/home/lasha/bashguard/bash_test_dataset/secure.list", "r") as f:
    secure_list = f.readlines()

with open("/home/lasha/bashguard/bash_test_dataset/vulnerable.list", "r") as f:
    vulnerable_list = f.readlines()

secure_scripts = []
vulnerable_scripts = []

for secure_script in secure_list:
    secure_scripts.append(record_script_analysis(secure_script.strip()))

for vulnerable_script in vulnerable_list:
    vulnerable_scripts.append(record_script_analysis(vulnerable_script.strip()))

print("secure scripts:")
secure_report = Report(secure_scripts)
secure_report.generate_report()

print("vulnerable scripts:")
vulnerable_report = Report(vulnerable_scripts)
vulnerable_report.generate_report()


print("total before fixing secure scripts:")
secure_before_stats = secure_report.get_total_before_fixing().get_stats()
for k, v in secure_before_stats.items():
    print(f"{k}: {len(v)}")

print("total after fixing secure scripts:")
secure_after_stats = secure_report.get_total_after_fixing().get_stats()
for k, v in secure_after_stats.items():
    print(f"{k}: {len(v)}")

print("total before fixing vulnerable scripts:")
vulnerable_before_stats = vulnerable_report.get_total_before_fixing().get_stats()
for k, v in vulnerable_before_stats.items():
    print(f"{k}: {len(v)}")

print("total after fixing vulnerable scripts:")
vulnerable_after_stats = vulnerable_report.get_total_after_fixing().get_stats()
for k, v in vulnerable_after_stats.items():
    print(f"{k}: {len(v)}")