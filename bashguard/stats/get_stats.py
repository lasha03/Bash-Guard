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
            if script is None:
                continue
            # print(script.name)
            # print("before fixing:")

            stats = script.vulnerabilities_before_fixing.get_stats()
            for k, v in stats.items():
                self.total_before_fixing.record(k, v)
                # print(f"{k}: {len(v)}")
            # print('--------------------------------')
            # print("after fixing:")
            stats = script.vulnerabilities_after_fixing.get_stats()
            for k, v in stats.items():
                self.total_after_fixing.record(k, v)
                # print(f"{k}: {len(v)}")
            # print('--------------------------------')

    def get_total_before_fixing(self):
        return self.total_before_fixing
    
    def get_total_after_fixing(self):
        return self.total_after_fixing

failed_to_analyze = 0
failed_to_fix = 0

def analyze_script(script_path):
    try:
        analyzer = ScriptAnalyzer(script_path)
        vulnerabilities = analyzer.analyze()
        stats = Stats()
        stats.record_stats(vulnerabilities)
        return stats, vulnerabilities
    except Exception as e:
        global failed_to_analyze
        failed_to_analyze += 1
        # print(e)
        # print(f"Failed to analyze {script_path}")
        return None, None


def fix_script(script_path, vulnerabilities):
    try:
        if script_path.endswith(".sh"):
            fixed_script_path = script_path.replace(".sh", "_fixed.sh")
        else:
            fixed_script_path = script_path + "_fixed.sh"
        
        fixer = Fixer(script_path, output_path=fixed_script_path)
        fixer.fix(vulnerabilities)
        return fixed_script_path
    except Exception as e:
        global failed_to_fix
        failed_to_fix += 1
        return None
        # print(e)
        # print(f"Failed to fix {script_path}")


def record_script_analysis(script_path):
    vulnerabilities_stats, vulnerabilities = analyze_script(script_path)
    if vulnerabilities_stats is None or vulnerabilities is None:
        return None

    fixed_script_path = fix_script(script_path, vulnerabilities)
    if fixed_script_path is None:
        return None
    
    vulnerabilities_fixed_stats, _ = analyze_script(fixed_script_path)
    if vulnerabilities_fixed_stats is None:
        return None
    
    return ScriptAnalysisResult(script_path, vulnerabilities_stats, vulnerabilities_fixed_stats)

secure_dir = "./scripts/secure_scripts"
vuln_dir = "./scripts/vuln_scripts"

secure_list = []
for root, dirs, files in os.walk(secure_dir):
    for fname in files:
        secure_list.append(os.path.join(root, fname))

vulnerable_list = []
for root, dirs, files in os.walk(vuln_dir):
    for fname in files:
        vulnerable_list.append(os.path.join(root, fname))

secure_scripts = []
vulnerable_scripts = []



for secure_script in secure_list:
    secure_scripts.append(record_script_analysis(secure_script.strip()))

for vulnerable_script in vulnerable_list:
    vulnerable_scripts.append(record_script_analysis(vulnerable_script.strip()))

# print("secure scripts:")
secure_report = Report(secure_scripts)
secure_report.generate_report()

# print("vulnerable scripts:")
vulnerable_report = Report(vulnerable_scripts)
vulnerable_report.generate_report()



print(f"TOTAL SECURE SCRIPTS: {len(secure_list)}")
print(f"TOTAL VULNERABLE SCRIPTS: {len(vulnerable_list)}")
print("--------------------------------")
print("TOTAL BEFORE FIXING SECURE SCRIPTS")
secure_before_stats = secure_report.get_total_before_fixing().get_stats()
for k, v in secure_before_stats.items():
    print(f"{k}: {len(v)}")

print("\n\nTOTAL AFTER FIXING SECURE SCRIPTS")
secure_after_stats = secure_report.get_total_after_fixing().get_stats()
for k, v in secure_after_stats.items():
    print(f"{k}: {len(v)}")

print("\n\n\nTOTAL BEFORE FIXING VULNERABLE SCRIPTS")
vulnerable_before_stats = vulnerable_report.get_total_before_fixing().get_stats()
for k, v in vulnerable_before_stats.items():
    print(f"{k}: {len(v)}")

print("\n\nTOTAL AFTER FIXING VULNERABLE SCRIPTS")
vulnerable_after_stats = vulnerable_report.get_total_after_fixing().get_stats()
for k, v in vulnerable_after_stats.items():
    print(f"{k}: {len(v)}")

print("\n\nFAILED TO ANALYZE: ", failed_to_analyze)
print("FAILED TO FIX: ", failed_to_fix)