#!/usr/bin/env python3
"""Script to integrate batch check implementations into aws_connector.py."""

import json
import os
import re
from typing import Dict, List, Any


def load_generated_config(filename: str) -> Dict[str, Any]:
    """Load generated check configurations."""
    with open(filename, 'r') as f:
        return json.load(f)


def load_existing_config(filename: str) -> Dict[str, Any]:
    """Load existing check configurations."""
    with open(filename, 'r') as f:
        return json.load(f)


def merge_configs(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Merge new check configurations with existing ones."""
    merged = existing.copy()
    
    # Add new checks to the security_checks list
    if 'security_checks' in merged and 'security_checks' in new:
        merged['security_checks'].extend(new['security_checks'])
    
    return merged


def generate_integration_code(batch_number: int, check_ids: List[str]) -> str:
    """Generate code to integrate batch checks into aws_connector.py."""
    
    imports = f"from check_implementations_batch{batch_number} import Batch{batch_number}SecurityChecks\n"
    
    mixin_code = f"""
    # Batch {batch_number} checks integration
    # Add this to the SecurityCheck class inheritance:
    # class SecurityCheck(Batch{batch_number}SecurityChecks):
    
    # Or add these method calls to the appropriate location:
"""
    
    for check_id in check_ids:
        method_name = f"check_{check_id.lower().replace('-', '_')}"
        mixin_code += f"""
    def {method_name}(self) -> List[Dict[str, Any]]:
        \"\"\"Wrapper for batch {batch_number} implementation.\"\"\"
        return Batch{batch_number}SecurityChecks.{method_name}(self)
"""
    
    return imports + mixin_code


def create_batch_summary(batch_number: int, configs: List[Dict[str, Any]]) -> str:
    """Create a summary of the batch checks."""
    
    summary = f"# Batch {batch_number} Security Checks Summary\n\n"
    summary += f"Total checks: {len(configs)}\n\n"
    
    # Group by category
    categories = {}
    for check in configs:
        category = check['category']
        if category not in categories:
            categories[category] = []
        categories[category].append(check)
    
    summary += "## Checks by Category:\n\n"
    for category, checks in sorted(categories.items()):
        summary += f"### {category} ({len(checks)} checks)\n"
        for check in checks:
            summary += f"- **{check['id']}**: {check['name']} ({check['severity']})\n"
            summary += f"  - NIST: {', '.join(check['nist_mappings'])}\n"
            summary += f"  - Primary Framework: {check['frameworks']['primary']['name']}\n"
        summary += "\n"
    
    # Services used
    services = set()
    for check in configs:
        services.add(check['service'])
    
    summary += f"## AWS Services Used:\n"
    summary += ", ".join(sorted(services)) + "\n\n"
    
    # Framework coverage
    frameworks = {}
    for check in configs:
        primary = check['frameworks']['primary']['name']
        if primary not in frameworks:
            frameworks[primary] = 0
        frameworks[primary] += 1
        
        for additional in check['frameworks']['additional']:
            framework = additional['name']
            if framework not in frameworks:
                frameworks[framework] = 0
            frameworks[framework] += 1
    
    summary += "## Framework Coverage:\n"
    for framework, count in sorted(frameworks.items(), key=lambda x: x[1], reverse=True):
        summary += f"- {framework}: {count} checks\n"
    
    return summary


def main():
    """Main integration function."""
    
    # Load configurations
    print("Loading generated configurations...")
    generated_config = load_generated_config('generated_checks_config.json')
    
    # Extract check IDs
    check_ids = [check['id'] for check in generated_config['security_checks']]
    print(f"Found {len(check_ids)} new checks: {check_ids[0]} to {check_ids[-1]}")
    
    # Generate integration code
    integration_code = generate_integration_code(1, check_ids)
    
    with open('batch1_integration.py', 'w') as f:
        f.write(integration_code)
    
    print("Generated batch1_integration.py with integration code")
    
    # Create summary
    summary = create_batch_summary(1, generated_config['security_checks'])
    
    with open('batch1_summary.md', 'w') as f:
        f.write(summary)
    
    print("Generated batch1_summary.md with check summary")
    
    # Create merged configuration
    print("\nTo merge configurations:")
    print("1. Backup existing checks_config.json")
    print("2. Run: python3 merge_configs.py")
    print("3. Add batch check methods to aws_connector.py")
    print("4. Test the new checks")
    
    # Show next steps
    print("\nNext steps:")
    print("1. Review generated check implementations")
    print("2. Complete implementations for CHECK-047 to CHECK-060")
    print("3. Add the check methods to aws_connector.py")
    print("4. Update checks_config.json with new check definitions")
    print("5. Test each new check individually")


if __name__ == "__main__":
    main() 