#!/usr/bin/env python3
"""Merge generated check configurations into the main checks_config.json."""

import json
import os
import shutil
from datetime import datetime


def backup_file(filepath):
    """Create a backup of the file."""
    backup_path = f"{filepath}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(filepath, backup_path)
    print(f"Created backup: {backup_path}")
    return backup_path


def load_json_file(filepath):
    """Load JSON from file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def save_json_file(filepath, data):
    """Save JSON to file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def merge_checks(existing_checks, new_checks):
    """Merge new checks into existing list."""
    # Create a set of existing check IDs
    existing_ids = {check['id'] for check in existing_checks}
    
    # Add only new checks that don't already exist
    merged_checks = existing_checks.copy()
    added_count = 0
    
    for check in new_checks:
        if check['id'] not in existing_ids:
            merged_checks.append(check)
            added_count += 1
            print(f"Added: {check['id']} - {check['name']}")
        else:
            print(f"Skipped (already exists): {check['id']}")
    
    return merged_checks, added_count


def main():
    """Main merge function."""
    # File paths
    existing_config_path = "../security_checks/checks_config.json"
    generated_config_path = "generated_checks_config.json"
    
    # Check if files exist
    if not os.path.exists(existing_config_path):
        print(f"Error: {existing_config_path} not found")
        return
        
    if not os.path.exists(generated_config_path):
        print(f"Error: {generated_config_path} not found")
        print("Run the check generator first to create this file")
        return
    
    # Backup existing config
    print("Backing up existing configuration...")
    backup_path = backup_file(existing_config_path)
    
    # Load configurations
    print("\nLoading configurations...")
    existing_config = load_json_file(existing_config_path)
    generated_config = load_json_file(generated_config_path)
    
    # Get check lists
    existing_checks = existing_config.get('security_checks', [])
    new_checks = generated_config.get('security_checks', [])
    
    print(f"\nExisting checks: {len(existing_checks)}")
    print(f"New checks to add: {len(new_checks)}")
    
    # Merge checks
    print("\nMerging checks...")
    merged_checks, added_count = merge_checks(existing_checks, new_checks)
    
    # Update the configuration
    existing_config['security_checks'] = merged_checks
    
    # Save merged configuration
    print(f"\nSaving merged configuration...")
    save_json_file(existing_config_path, existing_config)
    
    print(f"\nMerge complete!")
    print(f"Total checks: {len(merged_checks)}")
    print(f"New checks added: {added_count}")
    print(f"\nBackup saved at: {backup_path}")
    
    # Verify check IDs are sequential
    check_ids = sorted([check['id'] for check in merged_checks])
    print(f"\nCheck ID range: {check_ids[0]} to {check_ids[-1]}")
    
    # Check for missing IDs
    expected_ids = [f"CHECK-{i:03d}" for i in range(1, len(check_ids) + 1)]
    missing_ids = set(expected_ids) - set(check_ids)
    if missing_ids:
        print(f"Warning: Missing check IDs: {sorted(missing_ids)}")


if __name__ == "__main__":
    main() 