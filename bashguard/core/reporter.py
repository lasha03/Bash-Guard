"""
Reporter utilities for generating vulnerability reports.
"""

import json
from pathlib import Path
from typing import List
from colorama import Fore, Style, init

from bashguard.core import Vulnerability, SeverityLevel

# Initialize colorama
init()


class Reporter:
    """
    Reporter class for generating vulnerability reports in different formats.
    Uses Factory pattern to create different report formats.
    """
    
    def __init__(self, file_path: Path | None = None, format: str = "text"):
        """
        Initialize the reporter.
        
        Args:
            format: The output format (text, json, html)
        """
        self.file_path = file_path
        self.format = format
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """
        Generate a report from the list of vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities found
            
        Returns:
            Report string in the specified format
        """
        if self.format == "text":
            return self._generate_text_report(vulnerabilities)
        elif self.format == "json":
            return self._generate_json_report(vulnerabilities)
        elif self.format == "html":
            return self._generate_html_report(vulnerabilities)
        else:
            raise ValueError(f"Unsupported format: {self.format}")
    
    def _generate_text_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate a text report."""
        if not vulnerabilities:
            return "No vulnerabilities found."
        
        report = ["BashGuard Security Analysis Report", "=" * 40, "", f'File: {self.file_path if self.file_path else "stdin"}', ""]
        report.append(f"Total vulnerabilities found: {len(vulnerabilities)}")
        
        # Group by severity
        by_severity = {
            SeverityLevel.CRITICAL: [],
            SeverityLevel.HIGH: [],
            SeverityLevel.MEDIUM: [],
            SeverityLevel.LOW: []
        }
        
        for vuln in vulnerabilities:
            by_severity[vuln.severity].append(vuln)
        
        report.append(f"Critical: {len(by_severity[SeverityLevel.CRITICAL])}")
        report.append(f"High: {len(by_severity[SeverityLevel.HIGH])}")
        report.append(f"Medium: {len(by_severity[SeverityLevel.MEDIUM])}")
        report.append(f"Low: {len(by_severity[SeverityLevel.LOW])}")
        report.append("")
        
        # Sort vulnerabilities by severity (critical first)
        sorted_vulns: list[Vulnerability] = []
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            sorted_vulns.extend(by_severity[severity])
        
        # Detail each vulnerability
        for i, vuln in enumerate(sorted_vulns, 1):
            # Choose color based on severity
            if vuln.severity == SeverityLevel.CRITICAL:
                color = Fore.RED + Style.BRIGHT
            elif vuln.severity == SeverityLevel.HIGH:
                color = Fore.RED
            elif vuln.severity == SeverityLevel.MEDIUM:
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
            
            report.append(f"{color}[{i}] {vuln.vulnerability_type.name} ({vuln.severity.name}){Style.RESET_ALL}")
            report.append(f"Line {vuln.line_number}:")

            if vuln.line_content:
                report.append(vuln.line_content)

                # add Shellcheck-like pointer
                col = (vuln.column or 1) - 1
                pointer = (" " * col) + "^--- " + vuln.description + '\n'
                report.append(pointer)

                # follow with recommendation (if exists)
                if vuln.recommendation:
                    report.append(f"Recommendation: {vuln.recommendation}")

            else:
                # Fallback for cases without line content
                report.append(f"Description: {vuln.description}")
                if vuln.recommendation:
                    report.append(f"Recommendation: {vuln.recommendation}")
            
            if vuln.references:
                report.append("References:")
                for ref in vuln.references:
                    report.append(f"  - {ref}")
            
            report.append("")
        
        return "\n".join(report)
    
    def _generate_json_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate a JSON report."""
        severity_counts = {
            SeverityLevel.CRITICAL.name: 0,
            SeverityLevel.HIGH.name: 0,
            SeverityLevel.MEDIUM.name: 0,
            SeverityLevel.LOW.name: 0
        }

        for vuln in vulnerabilities:
            severity_counts[vuln.severity.name] += 1
        
        report_data = {
            "summary": {
                "total": len(vulnerabilities),
                "by_severity": severity_counts
            },
            "vulnerabilities": []
        }
        
        for vuln in vulnerabilities:
            vuln_data = {
                "type": vuln.vulnerability_type.name,
                "severity": vuln.severity.name,
                "description": vuln.description,
                "location": {
                    "file": str(vuln.file_path) if vuln.file_path else 'stdin',
                    "line": vuln.line_number,
                }
            }

            if vuln.column:
                vuln_data["location"]["column"] = vuln.column
            
            if vuln.line_content:
                vuln_data["code"] = vuln.line_content
            
            if vuln.recommendation:
                vuln_data["recommendation"] = str(vuln.recommendation)
            
            if vuln.references:
                vuln_data["references"] = vuln.references
            
            if vuln.metadata:
                vuln_data["metadata"] = vuln.metadata
            
            report_data["vulnerabilities"].append(vuln_data)
        
        return json.dumps(report_data, indent=4)
