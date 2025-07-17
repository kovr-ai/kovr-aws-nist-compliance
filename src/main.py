#!/usr/bin/env python3
"""Enhanced main application using modular checks and parallel execution."""

import json
import logging
import os
import sys
from datetime import datetime, timezone

import click

from aws_connector import AWSConnector
from enhanced_executor import EnhancedExecutor
from multi_framework_reporter import MultiFrameworkReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_framework_mappings():
    """Load framework mapping configurations."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Load framework mappings
    mappings_path = os.path.join(base_dir, "security_checks", "mappings", "frameworks.json")
    with open(mappings_path, "r") as f:
        framework_mappings = json.load(f)
    
    # Load NIST 800-53 mappings
    nist_53_path = os.path.join(base_dir, "mappings", "nist_800_53_mappings.json")
    with open(nist_53_path, "r") as f:
        nist_800_53_mappings = json.load(f)
    
    # Load NIST 800-171 mappings
    nist_171_path = os.path.join(base_dir, "mappings", "nist_800_171_mappings.json")
    with open(nist_171_path, "r") as f:
        nist_800_171_mappings = json.load(f)
    
    return framework_mappings, nist_800_53_mappings, nist_800_171_mappings


@click.command()
@click.option("--access-key", envvar="AWS_ACCESS_KEY_ID", help="AWS Access Key ID")
@click.option("--secret-key", envvar="AWS_SECRET_ACCESS_KEY", help="AWS Secret Access Key")
@click.option("--session-token", envvar="AWS_SESSION_TOKEN", help="AWS Session Token")
@click.option("--region", default="us-east-1", help="AWS Region")
@click.option("--output-dir", default="./reports", help="Output directory for reports")
@click.option("--checks", multiple=True, help="Specific check IDs to run")
@click.option("--skip-checks", multiple=True, help="Check IDs to skip")
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    help="Minimum severity level to check",
)
@click.option(
    "--format",
    type=click.Choice(["all", "csv", "nist-53", "nist-171", "multi-framework", "json"]),
    default="all",
    help="Report format to generate",
)
@click.option(
    "--parallel/--no-parallel",
    default=True,
    help="Enable parallel execution"
)
@click.option(
    "--workers",
    type=int,
    default=20,
    help="Number of parallel workers (default: 20)"
)
@click.option(
    "--all-regions/--single-region",
    default=True,
    help="Check all regions or just specified region"
)
@click.option(
    "--analyze-coverage",
    is_flag=True,
    help="Analyze framework coverage instead of running checks"
)
def main(
    access_key,
    secret_key,
    session_token,
    region,
    output_dir,
    checks,
    skip_checks,
    severity,
    format,
    parallel,
    workers,
    all_regions,
    analyze_coverage
):
    """AWS Multi-Framework Compliance Checker - Enhanced Version.
    
    This tool runs 160 security checks across 50+ AWS services and maps
    findings to multiple compliance frameworks including NIST 800-53,
    NIST 800-171, CIS, MITRE ATT&CK, and more.
    """
    logger.info("Starting AWS Multi-Framework Compliance Checker (Enhanced)")
    logger.info(f"Configuration: parallel={parallel}, workers={workers}, all_regions={all_regions}")
    
    # Handle coverage analysis mode
    if analyze_coverage:
        from coverage_analyzer import CoverageAnalyzer
        
        logger.info("Running framework coverage analysis...")
        analyzer = CoverageAnalyzer()
        report = analyzer.generate_coverage_report()
        
        # Save report
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, f"coverage_analysis_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md")
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"\nCoverage analysis complete!")
        print(f"Report saved to: {report_path}")
        
        # Print summary
        coverage = analyzer.analyze_nist_coverage()
        if 'nist_800_53' in coverage:
            data = coverage['nist_800_53']
            print(f"\nNIST 800-53: {data['covered_controls']}/{data['total_controls']} controls ({data['coverage_percentage']:.1f}%)")
        if 'nist_800_171' in coverage:
            data = coverage['nist_800_171']
            print(f"NIST 800-171: {data['covered_requirements']}/{data['total_requirements']} requirements ({data['coverage_percentage']:.1f}%)")
        
        return
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize AWS connector
    try:
        aws_connector = AWSConnector(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            region=region
        )
        logger.info(f"Connected to AWS account: {aws_connector.account_id}")
    except Exception as e:
        logger.error(f"Failed to connect to AWS: {e}")
        sys.exit(2)
    
    # Determine regions to check
    if all_regions:
        regions = aws_connector.get_all_regions()
        logger.info(f"Checking all {len(regions)} regions")
    else:
        regions = [region]
        logger.info(f"Checking single region: {region}")
    
    # Initialize executor
    executor = EnhancedExecutor(
        aws_connector=aws_connector,
        max_workers=workers if parallel else 1,
        progress_bar=True
    )
    
    # Parse comma-separated check lists
    parsed_checks = None
    if checks:
        parsed_checks = []
        for check_item in checks:
            if ',' in check_item:
                parsed_checks.extend(check_item.split(','))
            else:
                parsed_checks.append(check_item)
    
    parsed_skip_checks = None
    if skip_checks:
        parsed_skip_checks = []
        for skip_item in skip_checks:
            if ',' in skip_item:
                parsed_skip_checks.extend(skip_item.split(','))
            else:
                parsed_skip_checks.append(skip_item)
    
    # Execute checks
    start_time = datetime.now(timezone.utc)
    logger.info("Executing security checks...")
    
    results = executor.execute_all_checks(
        regions=regions,
        skip_checks=parsed_skip_checks,
        specific_checks=parsed_checks,
        min_severity=severity
    )
    
    execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(f"Completed {len(results)} checks in {execution_time:.1f} seconds")
    
    # Load framework mappings
    framework_mappings, nist_800_53_mappings, nist_800_171_mappings = load_framework_mappings()
    
    # Generate reports
    logger.info("Generating compliance reports...")
    reporter = MultiFrameworkReporter(
        results=results,
        framework_mappings=framework_mappings,
        nist_800_53_mappings=nist_800_53_mappings,
        nist_800_171_mappings=nist_800_171_mappings
    )
    
    # Generate requested reports
    if format == "all":
        report_paths = reporter.generate_all_reports(output_dir)
    else:
        report_paths = {}
        if format == "csv":
            report_paths["csv"] = reporter.generate_enhanced_csv_report(output_dir)
        elif format == "nist-53":
            report_paths["nist_800_53"] = reporter.generate_nist_800_53_report(output_dir)
        elif format == "nist-171":
            report_paths["nist_800_171"] = reporter.generate_nist_800_171_report(output_dir)
        elif format == "multi-framework":
            report_paths["cross_framework"] = reporter.generate_cross_framework_matrix(output_dir)
        elif format == "json":
            report_paths["evidence"] = reporter.generate_evidence_summary(output_dir)
    
    # Summary statistics
    total_checks = len(results)
    failed_checks = sum(1 for r in results if r['status'] == 'FAIL')
    error_checks = sum(1 for r in results if r['status'] == 'ERROR')
    passed_checks = total_checks - failed_checks - error_checks
    
    logger.info(f"\nCompliance Summary:")
    logger.info(f"  Total Checks: {total_checks}")
    logger.info(f"  Passed: {passed_checks} ({passed_checks/total_checks*100:.1f}%)")
    logger.info(f"  Failed: {failed_checks} ({failed_checks/total_checks*100:.1f}%)")
    logger.info(f"  Errors: {error_checks} ({error_checks/total_checks*100:.1f}%)")
    
    logger.info(f"\nReports generated in: {output_dir}")
    for report_type, path in report_paths.items():
        logger.info(f"  {report_type}: {os.path.basename(path)}")
    
    # Exit code based on findings
    if error_checks > 0:
        sys.exit(2)  # Errors occurred
    elif failed_checks > 0:
        sys.exit(1)  # Compliance failures
    else:
        sys.exit(0)  # All checks passed


if __name__ == "__main__":
    main()