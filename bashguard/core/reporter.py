"""
Reporter utilities for generating vulnerability reports.
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from colorama import Fore, Style, init
from bashguard.core.logger import Logger

from bashguard.core.vulnerability import Vulnerability, SeverityLevel

# Initialize colorama
init()


class Reporter:
    """
    Reporter class for generating vulnerability reports in different formats.
    Uses Factory pattern to create different report formats.
    """
    
    def __init__(self, file_path: Path, format: str = "text"):
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
        
        report = ["BashGuard Security Analysis Report", "=" * 40, "", f'File: {self.file_path}', ""]
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
                    "file": str(vuln.file_path),
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
    
    def _generate_html_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate an HTML report."""
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>BashGuard Security Analysis Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; }",
            "        h1 { color: #333; }",
            "        .summary { margin: 20px 0; }",
            "        .vulnerability { border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }",
            "        .critical { border-left: 5px solid #d9534f; }",
            "        .high { border-left: 5px solid #f0ad4e; }",
            "        .medium { border-left: 5px solid #5bc0de; }",
            "        .low { border-left: 5px solid #5cb85c; }",
            "        .code { background-color: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }",
            "    </style>",
            "</head>",
            "<body>",
            "    <h1>BashGuard Security Analysis Report</h1>",
            "    <div class='summary'>",
            f"        <p><strong>Total vulnerabilities found:</strong> {len(vulnerabilities)}</p>",
            f"        <p><strong>Critical:</strong> {len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL])}</p>",
            f"        <p><strong>High:</strong> {len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH])}</p>",
            f"        <p><strong>Medium:</strong> {len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM])}</p>",
            f"        <p><strong>Low:</strong> {len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW])}</p>",
            "    </div>",
            "    <h2>Vulnerabilities</h2>"
        ]
        
        # Sort vulnerabilities by severity (critical first)
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: [
                SeverityLevel.CRITICAL, SeverityLevel.HIGH, 
                SeverityLevel.MEDIUM, SeverityLevel.LOW
            ].index(v.severity)
        )
        
        for i, vuln in enumerate(sorted_vulns, 1):
            severity_class = vuln.severity.name.lower()
            html_parts.extend([
                f"    <div class='vulnerability {severity_class}'>",
                f"        <h3>{i}. {vuln.vulnerability_type.name} ({vuln.severity.name})</h3>",
                f"        <p><strong>File:</strong> {vuln.file_path}</p>",
                f"        <p><strong>Line:</strong> {vuln.line_number}" + (f", <strong>Column:</strong> {vuln.column}" if vuln.column else "") + "</p>",
                f"        <p><strong>Description:</strong> {vuln.description}</p>"
            ])
            
            if vuln.line_content:
                html_parts.append(f"        <div class='code'>{vuln.line_content}</div>")
            
            if vuln.recommendation:
                html_parts.append(f"        <p><strong>Recommendation:</strong> {vuln.recommendation}</p>")
            
            if vuln.references:
                html_parts.append("        <p><strong>References:</strong></p>")
                html_parts.append("        <ul>")
                for ref in vuln.references:
                    html_parts.append(f"            <li>{ref}</li>")
                html_parts.append("        </ul>")
            
            html_parts.append("    </div>")
        
        html_parts.extend([
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html_parts) 