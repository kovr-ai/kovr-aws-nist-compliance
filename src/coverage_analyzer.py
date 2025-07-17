#!/usr/bin/env python3
"""Framework coverage analysis utilities for the compliance checker."""

import json
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, Set, Tuple, Any


class CoverageAnalyzer:
    """Analyze compliance framework coverage for security checks."""
    
    def __init__(self, framework_mappings_path: str = "security_checks/mappings/frameworks.json",
                 nist_53_path: str = "mappings/nist_800_53_mappings.json",
                 nist_171_path: str = "security_checks/mappings/nist_800_171.json"):
        """Initialize the coverage analyzer with mapping files."""
        # Load framework mappings
        with open(framework_mappings_path, 'r') as f:
            self.frameworks = json.load(f)
        
        # Load NIST mappings
        try:
            with open(nist_53_path, 'r') as f:
                self.nist_800_53 = json.load(f)
        except:
            self.nist_800_53 = None
            
        try:
            with open(nist_171_path, 'r') as f:
                self.nist_800_171 = json.load(f)
        except:
            self.nist_800_171 = None
    
    def analyze_nist_coverage(self) -> Dict[str, Any]:
        """Analyze coverage for NIST frameworks."""
        results = {}
        
        # NIST 800-53 Analysis
        if self.nist_800_53:
            results['nist_800_53'] = self._analyze_800_53_coverage()
        
        # NIST 800-171 Analysis
        if self.nist_800_171:
            results['nist_800_171'] = self._analyze_800_171_coverage()
        
        return results
    
    def _analyze_800_53_coverage(self) -> Dict[str, Any]:
        """Analyze NIST 800-53 coverage."""
        # Count total controls
        total_controls = 0
        for family in self.nist_800_53.get('control_families', {}).values():
            total_controls += len(family.get('controls', {}))
        
        # Get covered controls
        covered_controls = set()
        for check_data in self.frameworks.get('check_mappings', {}).values():
            controls = check_data.get('frameworks', {}).get('nist_800_53', [])
            covered_controls.update(controls)
        
        # Analyze by family
        family_coverage = {}
        for family_id, family_data in self.nist_800_53.get('control_families', {}).items():
            family_controls = set(family_data.get('controls', {}).keys())
            family_covered = family_controls.intersection(covered_controls)
            family_coverage[family_id] = {
                'name': family_data.get('name', ''),
                'total': len(family_controls),
                'covered': len(family_covered),
                'percentage': (len(family_covered) / len(family_controls) * 100) if family_controls else 0,
                'covered_controls': sorted(list(family_covered))
            }
        
        return {
            'total_controls': total_controls,
            'covered_controls': len(covered_controls),
            'coverage_percentage': (len(covered_controls) / total_controls * 100) if total_controls else 0,
            'family_coverage': family_coverage,
            'unique_controls': sorted(list(covered_controls))
        }
    
    def _analyze_800_171_coverage(self) -> Dict[str, Any]:
        """Analyze NIST 800-171 coverage."""
        # NIST 800-171 has 110 requirements total
        total_requirements = 110
        
        # Get covered requirements
        covered_requirements = set()
        for check_data in self.frameworks.get('check_mappings', {}).values():
            requirements = check_data.get('frameworks', {}).get('nist_800_171', [])
            covered_requirements.update(requirements)
        
        # Analyze by requirement family
        family_coverage = defaultdict(lambda: {'total': 0, 'covered': 0, 'requirements': []})
        
        # Count requirements per family (based on known NIST 800-171 structure)
        requirement_families = {
            '3.1': {'name': 'Access Control', 'total': 22},
            '3.2': {'name': 'Awareness and Training', 'total': 3},
            '3.3': {'name': 'Audit and Accountability', 'total': 9},
            '3.4': {'name': 'Configuration Management', 'total': 9},
            '3.5': {'name': 'Identification and Authentication', 'total': 11},
            '3.6': {'name': 'Incident Response', 'total': 3},
            '3.7': {'name': 'Maintenance', 'total': 6},
            '3.8': {'name': 'Media Protection', 'total': 9},
            '3.9': {'name': 'Personnel Security', 'total': 2},
            '3.10': {'name': 'Physical Protection', 'total': 6},
            '3.11': {'name': 'Risk Assessment', 'total': 3},
            '3.12': {'name': 'Security Assessment', 'total': 4},
            '3.13': {'name': 'System and Communications Protection', 'total': 17},
            '3.14': {'name': 'System and Information Integrity', 'total': 7}
        }
        
        # Count covered requirements by family
        for req in covered_requirements:
            family = req.split('.')[0] + '.' + req.split('.')[1] if '.' in req else 'Unknown'
            if family in requirement_families:
                family_coverage[family]['covered'] += 1
                family_coverage[family]['requirements'].append(req)
        
        # Build final family coverage data
        final_family_coverage = {}
        for family_id, family_info in requirement_families.items():
            covered = family_coverage[family_id]['covered']
            total = family_info['total']
            final_family_coverage[family_id] = {
                'name': family_info['name'],
                'total': total,
                'covered': covered,
                'percentage': (covered / total * 100) if total else 0,
                'covered_requirements': sorted(family_coverage[family_id]['requirements'])
            }
        
        return {
            'total_requirements': total_requirements,
            'covered_requirements': len(covered_requirements),
            'coverage_percentage': (len(covered_requirements) / total_requirements * 100),
            'family_coverage': final_family_coverage,
            'unique_requirements': sorted(list(covered_requirements))
        }
    
    def generate_coverage_report(self) -> str:
        """Generate a comprehensive coverage report."""
        coverage = self.analyze_nist_coverage()
        report = []
        
        report.append("# Compliance Framework Coverage Analysis")
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n## Summary")
        
        # NIST 800-53 Summary
        if 'nist_800_53' in coverage:
            data = coverage['nist_800_53']
            report.append(f"\n### NIST 800-53 Rev 5")
            report.append(f"- Total Controls: {data['total_controls']}")
            report.append(f"- Covered Controls: {data['covered_controls']}")
            report.append(f"- Coverage: {data['coverage_percentage']:.1f}%")
        
        # NIST 800-171 Summary
        if 'nist_800_171' in coverage:
            data = coverage['nist_800_171']
            report.append(f"\n### NIST 800-171 Rev 2")
            report.append(f"- Total Requirements: {data['total_requirements']}")
            report.append(f"- Covered Requirements: {data['covered_requirements']}")
            report.append(f"- Coverage: {data['coverage_percentage']:.1f}%")
        
        # Detailed family coverage
        if 'nist_800_53' in coverage:
            report.append("\n## NIST 800-53 Family Coverage")
            for family_id, family_data in sorted(coverage['nist_800_53']['family_coverage'].items()):
                if family_data['covered'] > 0:
                    report.append(f"\n### {family_id} - {family_data['name']}")
                    report.append(f"- Coverage: {family_data['covered']}/{family_data['total']} ({family_data['percentage']:.1f}%)")
                    report.append(f"- Controls: {', '.join(family_data['covered_controls'])}")
        
        if 'nist_800_171' in coverage:
            report.append("\n## NIST 800-171 Family Coverage")
            for family_id, family_data in sorted(coverage['nist_800_171']['family_coverage'].items()):
                if family_data['covered'] > 0:
                    report.append(f"\n### {family_id} - {family_data['name']}")
                    report.append(f"- Coverage: {family_data['covered']}/{family_data['total']} ({family_data['percentage']:.1f}%)")
                    report.append(f"- Requirements: {', '.join(family_data['covered_requirements'])}")
        
        return '\n'.join(report)
    
    def get_uncovered_controls(self, framework: str = 'nist_800_53') -> Set[str]:
        """Get list of uncovered controls for a framework."""
        coverage = self.analyze_nist_coverage()
        
        if framework == 'nist_800_53' and 'nist_800_53' in coverage:
            all_controls = set()
            for family_data in self.nist_800_53.get('control_families', {}).values():
                all_controls.update(family_data.get('controls', {}).keys())
            
            covered = set(coverage['nist_800_53']['unique_controls'])
            return all_controls - covered
        
        elif framework == 'nist_800_171' and 'nist_800_171' in coverage:
            # Generate all possible requirements
            all_requirements = set()
            for family_id, family_info in coverage['nist_800_171']['family_coverage'].items():
                for i in range(1, family_info['total'] + 1):
                    all_requirements.add(f"{family_id}.{i}")
            
            covered = set(coverage['nist_800_171']['unique_requirements'])
            return all_requirements - covered
        
        return set()


if __name__ == "__main__":
    from datetime import datetime
    
    # Run coverage analysis
    analyzer = CoverageAnalyzer()
    coverage = analyzer.analyze_nist_coverage()
    
    # Print summary
    print("NIST Framework Coverage Analysis")
    print("=" * 50)
    
    if 'nist_800_53' in coverage:
        data = coverage['nist_800_53']
        print(f"\nNIST 800-53 Rev 5:")
        print(f"  Total Controls: {data['total_controls']}")
        print(f"  Covered: {data['covered_controls']} ({data['coverage_percentage']:.1f}%)")
    
    if 'nist_800_171' in coverage:
        data = coverage['nist_800_171']
        print(f"\nNIST 800-171 Rev 2:")
        print(f"  Total Requirements: {data['total_requirements']}")
        print(f"  Covered: {data['covered_requirements']} ({data['coverage_percentage']:.1f}%)")
    
    # Generate detailed report
    report = analyzer.generate_coverage_report()
    
    # Save report
    report_path = f"reports/coverage_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    os.makedirs("reports", exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\nDetailed report saved to: {report_path}")