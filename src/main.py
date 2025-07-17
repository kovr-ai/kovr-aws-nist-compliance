#!/usr/bin/env python3
"""Main application for AWS NIST 800-53 compliance checking."""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
import subprocess
import tempfile
import shutil

import click
from aws_connector import AWSConnector, SecurityCheck
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_configurations():
    """Load security checks and NIST mappings configurations."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Load security checks
    checks_path = os.path.join(base_dir, '..', 'security_checks', 'checks_config.json')
    with open(checks_path, 'r') as f:
        security_checks = json.load(f)
    
    # Load NIST mappings
    mappings_path = os.path.join(base_dir, '..', 'mappings', 'nist_800_53_mappings.json')
    with open(mappings_path, 'r') as f:
        nist_mappings = json.load(f)
    
    return security_checks, nist_mappings


def download_from_git(repo_url: str, branch: str = 'main') -> str:
    """Download security checks from git repository."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clone the repository
        logger.info(f"Cloning repository from {repo_url}")
        subprocess.run([
            'git', 'clone', '--depth', '1', '--branch', branch, repo_url, temp_dir
        ], check=True, capture_output=True, text=True)
        
        return temp_dir
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {e}")
        shutil.rmtree(temp_dir)
        raise


@click.command()
@click.option('--access-key', envvar='AWS_ACCESS_KEY_ID', help='AWS Access Key ID')
@click.option('--secret-key', envvar='AWS_SECRET_ACCESS_KEY', help='AWS Secret Access Key')
@click.option('--session-token', envvar='AWS_SESSION_TOKEN', help='AWS Session Token')
@click.option('--region', default='us-east-1', help='AWS Region')
@click.option('--git-repo', help='Git repository URL for security checks')
@click.option('--git-branch', default='main', help='Git branch to use')
@click.option('--output-dir', default='./reports', help='Output directory for reports')
@click.option('--checks', multiple=True, help='Specific check IDs to run')
@click.option('--skip-checks', multiple=True, help='Check IDs to skip')
@click.option('--severity', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), 
              help='Minimum severity level to check')
@click.option('--format', type=click.Choice(['all', 'csv', 'markdown', 'json']), 
              default='all', help='Report format to generate')
def main(access_key, secret_key, session_token, region, git_repo, git_branch, 
         output_dir, checks, skip_checks, severity, format):
    """AWS NIST 800-53 Compliance Checker"""
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          AWS NIST 800-53 Compliance Checker               ║
    ║                    Version 1.0.0                          ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Handle git repository download if specified
        temp_dir = None
        if git_repo:
            temp_dir = download_from_git(git_repo, git_branch)
            # Add temp directory to Python path
            sys.path.insert(0, temp_dir)
        
        # Load configurations
        logger.info("Loading security check configurations...")
        security_checks, nist_mappings = load_configurations()
        
        # Initialize AWS connector
        logger.info("Connecting to AWS...")
        aws_connector = AWSConnector(
            session_token=session_token,
            access_key=access_key,
            secret_key=secret_key,
            region=region
        )
        logger.info(f"Connected to AWS account: {aws_connector.account_id}")
        
        # Initialize security checker
        security_checker = SecurityCheck(aws_connector)
        
        # Filter checks based on options
        checks_to_run = security_checks['security_checks']
        
        if checks:
            checks_to_run = [c for c in checks_to_run if c['id'] in checks]
        
        if skip_checks:
            checks_to_run = [c for c in checks_to_run if c['id'] not in skip_checks]
        
        if severity:
            severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            min_severity = severity_order[severity]
            checks_to_run = [c for c in checks_to_run 
                           if severity_order.get(c['severity'], 0) >= min_severity]
        
        # Run security checks
        logger.info(f"Running {len(checks_to_run)} security checks...")
        results = []
        
        with click.progressbar(checks_to_run, label='Running checks') as checks_bar:
            for check_config in checks_bar:
                result = security_checker.run_check(check_config)
                results.append(result)
                
                # Log failures immediately
                if result['status'] == 'FAIL':
                    logger.warning(f"Check {result['check_id']} failed with {len(result['findings'])} findings")
        
        # Generate reports
        logger.info("Generating compliance reports...")
        report_generator = ReportGenerator(results, nist_mappings)
        
        generated_reports = []
        
        if format in ['all', 'csv']:
            csv_path = report_generator.generate_csv_report(output_dir)
            generated_reports.append(csv_path)
        
        if format in ['all', 'markdown']:
            md_path = report_generator.generate_markdown_report(output_dir)
            generated_reports.append(md_path)
        
        if format in ['all', 'json']:
            json_path = report_generator.generate_summary_json(output_dir)
            generated_reports.append(json_path)
        
        # Print summary
        print("\n" + "="*60)
        print("COMPLIANCE CHECK SUMMARY")
        print("="*60)
        
        total_checks = len(results)
        passed_checks = sum(1 for r in results if r['status'] == 'PASS')
        failed_checks = sum(1 for r in results if r['status'] == 'FAIL')
        error_checks = sum(1 for r in results if r['status'] == 'ERROR')
        
        print(f"Total Checks: {total_checks}")
        print(f"Passed: {passed_checks} ({(passed_checks/total_checks)*100:.1f}%)")
        print(f"Failed: {failed_checks} ({(failed_checks/total_checks)*100:.1f}%)")
        print(f"Errors: {error_checks}")
        print("\nReports generated:")
        for report in generated_reports:
            print(f"  - {report}")
        
        # Cleanup temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)
        
        # Exit with appropriate code
        sys.exit(0 if failed_checks == 0 else 1)
        
    except Exception as e:
        logger.error(f"Error during compliance check: {str(e)}")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        sys.exit(2)


if __name__ == '__main__':
    main()