#!/usr/bin/env python3
"""Test script to demonstrate performance improvements."""

import time
import subprocess
import json
import os

def run_compliance_check(parallel=False):
    """Run compliance check and return timing information."""
    cmd = ["./run_compliance_check.sh", "-f", "json"]
    
    if parallel:
        cmd.extend(["-p", "-w", "10", "-m"])
        
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    end_time = time.time()
    
    return {
        'execution_time': end_time - start_time,
        'exit_code': result.returncode,
        'parallel': parallel
    }

def main():
    """Compare sequential and parallel execution."""
    print("Performance Comparison Test")
    print("=" * 50)
    
    # Ensure we have AWS credentials
    if not os.environ.get('AWS_ACCESS_KEY_ID'):
        print("Error: AWS credentials not found")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        return
    
    # Run sequential test
    print("\n1. Running SEQUENTIAL execution...")
    seq_result = run_compliance_check(parallel=False)
    print(f"   Completed in: {seq_result['execution_time']:.2f} seconds")
    
    # Run parallel test
    print("\n2. Running PARALLEL execution...")
    par_result = run_compliance_check(parallel=True)
    print(f"   Completed in: {par_result['execution_time']:.2f} seconds")
    
    # Calculate improvement
    improvement = ((seq_result['execution_time'] - par_result['execution_time']) / 
                  seq_result['execution_time'] * 100)
    speedup = seq_result['execution_time'] / par_result['execution_time']
    
    print("\n" + "=" * 50)
    print("RESULTS:")
    print(f"Sequential execution: {seq_result['execution_time']:.2f}s")
    print(f"Parallel execution:   {par_result['execution_time']:.2f}s")
    print(f"Performance improvement: {improvement:.1f}%")
    print(f"Speedup factor: {speedup:.2f}x")
    
    # Check if performance report was generated
    reports_dir = "./reports"
    perf_reports = [f for f in os.listdir(reports_dir) if f.startswith("performance_report_")]
    
    if perf_reports:
        latest_report = max(perf_reports)
        with open(os.path.join(reports_dir, latest_report), 'r') as f:
            perf_data = json.load(f)
            
        print("\nPerformance Metrics:")
        if 'summary' in perf_data:
            summary = perf_data['summary']
            print(f"  - Total API calls: {summary.get('total_api_calls', 0)}")
            print(f"  - Average time per check: {summary.get('average_check_time', 0):.2f}s")
            print(f"  - Checks per second: {summary.get('checks_per_second', 0):.2f}")
            
        if 'slow_checks' in perf_data and perf_data['slow_checks']:
            print("\n  Slowest checks:")
            for check in perf_data['slow_checks'][:5]:
                print(f"    - {check['check_id']}: {check['execution_time']:.2f}s")

if __name__ == "__main__":
    main() 