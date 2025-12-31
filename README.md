# cis-compliance-checker
**Python-based CIS compliance checking tool for system configuration auditing**

Organizations are required to comply with multiple security frameworks - whether it's HIPAA for healthcare data, PCI-DSS for payment cards, SOC 2 for SaaS companies, or ISO 27001 for international operations. Compliance audits are expensive, time-consuming, and often manual. A single audit can cost $50,000-$200,000+ annually, and failing an audit can result in fines, lost business, or reputational damage.

**My Solution**

I built an automated compliance checking tool that continuously validates system configurations against six major security frameworks. Instead of waiting for annual audits to discover issues, organizations can run daily automated checks and fix problems proactively.

**Technical Overview** 

-Reads Configuration Files: defined compliance requirements in structured YAML files rather than hardcoding them, making it easy to add new frameworks or update requirements without changing code

-Executes System Checks: runs actual system commands to verify configurations (e.g., checks password policies, firewall settings, file permissions, user access controls)

-Evaluates Compliance: compares actual system state against required state and determines pass/fail

-Generates Reports: creates detailed reports in multiple formats (JSON for APIs, CSV for spreadsheets, text for humans) showing what passed, what failed, and how to fix issues

**Why This Architecture Matters**

**Config-Driven Design**: By separating compliance rules (benchmarks.yaml) from execution logic (Python script) and runtime settings (config.yaml), I demonstrated:

-Software engineering best practices

-Maintainability - new frameworks can be added without coding

-Scalability - can support unlimited checks

-Enterprise-ready design patterns
