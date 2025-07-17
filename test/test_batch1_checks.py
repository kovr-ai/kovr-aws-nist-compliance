#!/usr/bin/env python3
"""Test script for batch 1 security checks."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_connector import AWSConnector, SecurityCheck
import logging
from datetime import datetime
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_individual_check(check_id: str, aws_connector: AWSConnector) -> dict:
    """Test an individual check."""
    logger.info(f"\nTesting {check_id}...")
    
    security_check = SecurityCheck(aws_connector)
    
    # Get check function name
    check_function_name = f"check_{check_id.lower().replace('-', '_')}"
    
    try:
        # Check if method exists
        if not hasattr(security_check, check_function_name):
            return {
                'check_id': check_id,
                'status': 'ERROR',
                'error': f'Method {check_function_name} not found',
                'findings': []
            }
        
        # Run the check
        check_method = getattr(security_check, check_function_name)
        findings = check_method()
        
        return {
            'check_id': check_id,
            'status': 'SUCCESS',
            'findings_count': len(findings),
            'findings': findings[:3] if findings else []  # Show first 3 findings
        }
        
    except Exception as e:
        logger.error(f"Error testing {check_id}: {str(e)}")
        return {
            'check_id': check_id,
            'status': 'ERROR',
            'error': str(e),
            'findings': []
        }


def test_batch_1_checks():
    """Test all batch 1 checks."""
    print("\n" + "="*60)
    print("BATCH 1 SECURITY CHECKS TEST")
    print("="*60)
    
    # Initialize AWS connector
    print("\nInitializing AWS connector...")
    try:
        aws_connector = AWSConnector()
        print("✓ AWS connector initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize AWS connector: {str(e)}")
        return
    
    # List of batch 1 checks
    batch_1_checks = [f"CHECK-{i:03d}" for i in range(41, 61)]
    
    # Test results
    results = {
        'total': len(batch_1_checks),
        'success': 0,
        'error': 0,
        'checks': []
    }
    
    # Test each check
    for check_id in batch_1_checks:
        result = test_individual_check(check_id, aws_connector)
        results['checks'].append(result)
        
        if result['status'] == 'SUCCESS':
            results['success'] += 1
            print(f"✓ {check_id}: SUCCESS (found {result['findings_count']} findings)")
        else:
            results['error'] += 1
            print(f"✗ {check_id}: ERROR - {result['error']}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Total checks tested: {results['total']}")
    print(f"Successful: {results['success']}")
    print(f"Errors: {results['error']}")
    print(f"Success rate: {(results['success']/results['total'])*100:.1f}%")
    
    # Save detailed results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_file = f"test_batch1_results_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    
    # Show sample findings
    print("\n" + "="*60)
    print("SAMPLE FINDINGS")
    print("="*60)
    
    for check in results['checks'][:5]:  # Show first 5 checks
        if check['findings_count'] > 0:
            print(f"\n{check['check_id']} findings:")
            for finding in check['findings']:
                print(f"  - Type: {finding.get('type', 'N/A')}")
                print(f"    Resource: {finding.get('resource', 'N/A')}")
                print(f"    Details: {finding.get('details', 'N/A')}")


def test_specific_check(check_id: str):
    """Test a specific check with detailed output."""
    print(f"\nTesting {check_id} in detail...")
    
    # Initialize AWS connector
    try:
        aws_connector = AWSConnector()
    except Exception as e:
        print(f"Failed to initialize AWS connector: {str(e)}")
        return
    
    result = test_individual_check(check_id, aws_connector)
    
    print(f"\nResults for {check_id}:")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Test specific check
        check_id = sys.argv[1]
        test_specific_check(check_id)
    else:
        # Test all batch 1 checks
        test_batch_1_checks() 