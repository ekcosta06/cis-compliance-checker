#!/usr/bin/env python3
"""
Compliance Checker - Automated GRC Compliance Validation Tool
Supports CIS Benchmarks, NIST 800-53, and PCI-DSS
"""

import platform
import subprocess
import json
import yaml
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

class ComplianceChecker:
    def __init__(self, config_file: str = "config.yaml", benchmark_file: str = "benchmarks.yaml"):
        self.config = self.load_config(config_file)
        self.benchmarks = self.load_benchmarks(benchmark_file)
        self.system = platform.system()
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "system": self.system,
            "config": {
                "frameworks": self.config.get("frameworks", {}).get("enabled", []),
                "severity_filter": self.config.get("severity_filter", {}).get("levels", [])
            },
            "checks": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "not_applicable": 0,
                "by_severity": {},
                "by_framework": {}
            }
        }
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                print(f"✓ Loaded configuration from {config_file}")
                return config
        except FileNotFoundError:
            print(f"⚠ Config file not found: {config_file}, using defaults")
            return self.get_default_config()
        except Exception as e:
            print(f"✗ Error loading config: {e}")
            return self.get_default_config()
    
    def load_benchmarks(self, benchmark_file: str) -> Dict:
        """Load benchmark definitions from YAML file"""
        try:
            with open(benchmark_file, 'r') as f:
                benchmarks = yaml.safe_load(f)
                print(f"✓ Loaded benchmarks from {benchmark_file}")
                return benchmarks
        except FileNotFoundError:
            print(f"✗ Benchmark file not found: {benchmark_file}")
            return {"benchmarks": {}}
        except Exception as e:
            print(f"✗ Error loading benchmarks: {e}")
            return {"benchmarks": {}}
    
    def get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            "frameworks": {"enabled": ["cis_linux"]},
            "severity_filter": {"enabled": True, "levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "system": {"command_timeout": 10},
            "reporting": {
                "formats": ["json", "text"],
                "output_directory": "./compliance_reports",
                "detail_level": "detailed"
            }
        }
    
    def run_command(self, command: str) -> tuple[str, int]:
        """Execute system command and return output"""
        timeout = self.config.get("system", {}).get("command_timeout", 10)
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "Command timeout", -1
        except Exception as e:
            return str(e), -1
    
    def extract_value(self, output: str, pattern: str) -> Optional[str]:
        """Extract value from command output using regex pattern"""
        try:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        except Exception as e:
            print(f"⚠ Pattern extraction error: {e}")
        return None
    
    def evaluate_check(self, check: Dict, output: str, returncode: int) -> Dict:
        """Evaluate check result based on evaluation criteria"""
        result = {
            "id": check["id"],
            "title": check["title"],
            "description": check["description"],
            "severity": check["severity"],
            "category": check["category"],
            "framework": check["framework"],
            "status": "NOT_APPLICABLE",
            "details": "",
            "actual_value": None,
            "expected_value": None
        }
        
        # Add remediation and references if configured
        if self.config.get("reporting", {}).get("include_remediation", True):
            result["remediation"] = check.get("remediation", "")
        if self.config.get("reporting", {}).get("include_references", True):
            result["references"] = check.get("references", [])
        
        evaluation = check.get("evaluation", {})
        eval_type = evaluation.get("type")
        
        # Check if command executed successfully or has fallback
        if returncode != 0 and not check.get("fallback_command"):
            result["status"] = "NOT_APPLICABLE"
            result["details"] = "Command failed or not applicable to this system"
            return result
        
        try:
            if eval_type == "numeric_comparison":
                pattern = evaluation.get("extract_pattern")
                if pattern:
                    value_str = self.extract_value(output, pattern)
                    if value_str:
                        actual_value = int(value_str)
                        expected_value = evaluation.get("expected_value")
                        operator = evaluation.get("operator")
                        
                        result["actual_value"] = actual_value
                        result["expected_value"] = expected_value
                        
                        if operator == "<=":
                            result["status"] = "PASS" if actual_value <= expected_value else "FAIL"
                        elif operator == ">=":
                            result["status"] = "PASS" if actual_value >= expected_value else "FAIL"
                        elif operator == "==":
                            result["status"] = "PASS" if actual_value == expected_value else "FAIL"
                        
                        result["details"] = f"Actual: {actual_value}, Expected: {operator} {expected_value}"
            
            elif eval_type == "string_match":
                pattern = evaluation.get("extract_pattern")
                expected = evaluation.get("expected_value")
                
                if pattern:
                    actual_value = self.extract_value(output, pattern)
                else:
                    actual_value = output.strip().split()[-1] if output else None
                
                result["actual_value"] = actual_value
                result["expected_value"] = expected
                
                if actual_value:
                    result["status"] = "PASS" if actual_value.lower() == expected.lower() else "FAIL"
                    result["details"] = f"Actual: {actual_value}, Expected: {expected}"
                elif evaluation.get("default_pass"):
                    result["status"] = "PASS"
                    result["details"] = "Not explicitly set (using secure default)"
                else:
                    result["status"] = "FAIL"
                    result["details"] = f"Not configured, Expected: {expected}"
            
            elif eval_type == "string_contains":
                expected = evaluation.get("expected_value")
                result["expected_value"] = expected
                
                if expected.lower() in output.lower():
                    result["status"] = "PASS"
                    result["details"] = f"Found '{expected}' in output"
                else:
                    result["status"] = "FAIL"
                    result["details"] = f"'{expected}' not found in output"
            
            elif eval_type == "empty_output":
                if not output or output.strip() == "":
                    result["status"] = "PASS"
                    result["details"] = "No issues found"
                else:
                    result["status"] = "FAIL"
                    result["details"] = f"Found: {output[:200]}"
            
            elif eval_type == "permission_check":
                expected = evaluation.get("expected_value")
                acceptable = evaluation.get("acceptable_values", [expected])
                actual = output.strip()
                
                result["actual_value"] = actual
                result["expected_value"] = expected
                
                if actual in acceptable:
                    result["status"] = "PASS"
                    result["details"] = f"Permissions: {actual}"
                else:
                    result["status"] = "FAIL"
                    result["details"] = f"Actual: {actual}, Expected: {' or '.join(acceptable)}"
            
            else:
                result["status"] = "NOT_APPLICABLE"
                result["details"] = f"Unknown evaluation type: {eval_type}"
        
        except Exception as e:
            result["status"] = "FAIL"
            result["details"] = f"Evaluation error: {str(e)}"
        
        return result
    
    def should_run_check(self, check: Dict) -> bool:
        """Determine if a check should be run based on filters"""
        # Check system applicability
        applicable_systems = check.get("applicable_systems", [])
        if applicable_systems and self.system not in applicable_systems:
            return False
        
        # Check severity filter
        severity_config = self.config.get("severity_filter", {})
        if severity_config.get("enabled", True):
            allowed_severities = severity_config.get("levels", [])
            if check["severity"] not in allowed_severities:
                return False
        
        # Check ID filters
        filters = self.config.get("filters", {})
        include_ids = filters.get("include_check_ids", [])
        exclude_ids = filters.get("exclude_check_ids", [])
        
        if include_ids and check["id"] not in include_ids:
            return False
        if exclude_ids and check["id"] in exclude_ids:
            return False
        
        # Check category filters
        include_cats = filters.get("include_categories", [])
        exclude_cats = filters.get("exclude_categories", [])
        
        if include_cats and check["category"] not in include_cats:
            return False
        if exclude_cats and check["category"] in exclude_cats:
            return False
        
        return True
    
    def run_all_checks(self):
        """Run all enabled compliance checks"""
        enabled_frameworks = self.config.get("frameworks", {}).get("enabled", [])
        
        for framework_id in enabled_frameworks:
            framework = self.benchmarks.get("benchmarks", {}).get(framework_id, {})
            if not framework:
                print(f"⚠ Framework not found: {framework_id}")
                continue
            
            framework_name = framework.get("name", framework_id)
            checks = framework.get("checks", [])
            
            print(f"\n{'='*60}")
            print(f"Running {framework_name} checks...")
            print(f"{'='*60}")
            
            for check in checks:
                if not self.should_run_check(check):
                    continue
                
                print(f"  [{check['id']}] {check['title']}...", end=" ")
                
                # Run primary command
                command = check.get("command")
                output, returncode = self.run_command(command)
                
                # Try fallback if primary fails
                if returncode != 0 and check.get("fallback_command"):
                    command = check["fallback_command"]
                    output, returncode = self.run_command(command)
                
                # Evaluate result
                result = self.evaluate_check(check, output, returncode)
                self.results["checks"].append(result)
                
                # Update summary
                self.results["summary"]["total"] += 1
                status = result["status"]
                
                if status == "PASS":
                    self.results["summary"]["passed"] += 1
                    print("✓ PASS")
                elif status == "FAIL":
                    self.results["summary"]["failed"] += 1
                    print("✗ FAIL")
                else:
                    self.results["summary"]["not_applicable"] += 1
                    print("○ N/A")
                
                # Track by severity and framework
                severity = check["severity"]
                framework_key = check["framework"]
                
                if severity not in self.results["summary"]["by_severity"]:
                    self.results["summary"]["by_severity"][severity] = {"passed": 0, "failed": 0}
                if framework_key not in self.results["summary"]["by_framework"]:
                    self.results["summary"]["by_framework"][framework_key] = {"passed": 0, "failed": 0}
                
                if status == "PASS":
                    self.results["summary"]["by_severity"][severity]["passed"] += 1
                    self.results["summary"]["by_framework"][framework_key]["passed"] += 1
                elif status == "FAIL":
                    self.results["summary"]["by_severity"][severity]["failed"] += 1
                    self.results["summary"]["by_framework"][framework_key]["failed"] += 1
    
    def generate_report(self, output_format: str = "text") -> str:
        """Generate compliance report in specified format"""
        if output_format == "json":
            return json.dumps(self.results, indent=2)
        
        elif output_format == "text":
            lines = []
            lines.append("=" * 80)
            lines.append("COMPLIANCE CHECK REPORT")
            lines.append("=" * 80)
            lines.append(f"System: {self.results['system']}")
            lines.append(f"Timestamp: {self.results['timestamp']}")
            lines.append(f"Frameworks: {', '.join(self.results['config']['frameworks'])}")
            lines.append("")
            
            lines.append("SUMMARY:")
            summary = self.results['summary']
            lines.append(f"  Total Checks: {summary['total']}")
            lines.append(f"  Passed: {summary['passed']}")
            lines.append(f"  Failed: {summary['failed']}")
            lines.append(f"  Not Applicable: {summary['not_applicable']}")
            
            if summary['total'] > 0:
                pass_rate = (summary['passed'] / summary['total']) * 100
                lines.append(f"  Pass Rate: {pass_rate:.1f}%")
            
            # Breakdown by severity
            lines.append("\n  By Severity:")
            for severity, counts in summary.get('by_severity', {}).items():
                lines.append(f"    {severity}: {counts['passed']} passed, {counts['failed']} failed")
            
            # Breakdown by framework
            lines.append("\n  By Framework:")
            for framework, counts in summary.get('by_framework', {}).items():
                lines.append(f"    {framework}: {counts['passed']} passed, {counts['failed']} failed")
            
            lines.append("\n" + "=" * 80)
            lines.append("DETAILED RESULTS:")
            lines.append("=" * 80)
            
            # Group by framework
            by_framework = {}
            for check in self.results['checks']:
                fw = check['framework']
                if fw not in by_framework:
                    by_framework[fw] = []
                by_framework[fw].append(check)
            
            for framework, checks in by_framework.items():
                lines.append(f"\n{framework}:")
                lines.append("-" * 80)
                
                for check in checks:
                    status_icon = "✓" if check['status'] == "PASS" else "✗" if check['status'] == "FAIL" else "○"
                    lines.append(f"\n[{status_icon}] {check['id']}: {check['title']}")
                    lines.append(f"    Severity: {check['severity']}")
                    lines.append(f"    Category: {check['category']}")
                    lines.append(f"    Status: {check['status']}")
                    lines.append(f"    Details: {check['details']}")
                    
                    if check.get('remediation') and check['status'] == 'FAIL':
                        lines.append(f"    Remediation: {check['remediation']}")
            
            return "\n".join(lines)
        
        elif output_format == "csv":
            lines = ["ID,Title,Framework,Severity,Category,Status,Details"]
            for check in self.results['checks']:
                lines.append(f"{check['id']},{check['title']},{check['framework']},"
                           f"{check['severity']},{check['category']},{check['status']},"
                           f"\"{check['details']}\"")
            return "\n".join(lines)
        
        return "Unsupported format"
    
    def save_reports(self):
        """Save reports in configured formats"""
        output_dir = Path(self.config.get("reporting", {}).get("output_directory", "./compliance_reports"))
        output_dir.mkdir(exist_ok=True)
        
        formats = self.config.get("reporting", {}).get("formats", ["json", "text"])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in formats:
            report_content = self.generate_report(output_format=fmt)
            
            if self.config.get("reporting", {}).get("timestamp_filenames", True):
                filename = f"compliance_report_{timestamp}.{fmt}"
            else:
                filename = f"compliance_report.{fmt}"
            
            filepath = output_dir / filename
            with open(filepath, 'w') as f:
                f.write(report_content)
            
            print(f"✓ Saved {fmt.upper()} report to: {filepath}")

def main():
    print("=" * 80)
    print("GRC COMPLIANCE CHECKER")
    print("=" * 80)
    print(f"Detected OS: {platform.system()}\n")
    
    checker = ComplianceChecker(
        config_file="config.yaml",
        benchmark_file="benchmarks.yaml"
    )
    
    checker.run_all_checks()
    
    print("\n" + "=" * 80)
    print("GENERATING REPORTS")
    print("=" * 80)
    
    checker.save_reports()
    
    print("\n" + checker.generate_report(output_format="text"))
    print("\n✓ Compliance check complete!")

if __name__ == "__main__":
    main()