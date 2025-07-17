#!/usr/bin/env python3
"""Add batch check methods to aws_connector.py."""

import re
import shutil
from datetime import datetime


def backup_file(filepath):
    """Create a backup of the file."""
    backup_path = f"{filepath}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(filepath, backup_path)
    print(f"Created backup: {backup_path}")
    return backup_path


def generate_check_method(check_id: str) -> str:
    """Generate a check method that calls the batch implementation."""
    method_name = f"check_{check_id.lower().replace('-', '_')}"
    
    return f'''
    def {method_name}(self) -> List[Dict[str, Any]]:
        """Implementation for {check_id}."""
        # Implemented in check_implementations_batch1.py
        from check_implementations_batch1 import Batch1SecurityChecks
        return Batch1SecurityChecks.{method_name}(self)
'''


def add_batch_checks_to_connector():
    """Add batch check methods to aws_connector.py."""
    
    # Backup the file
    connector_path = "aws_connector.py"
    print(f"Backing up {connector_path}...")
    backup_path = backup_file(connector_path)
    
    # Read the current content
    with open(connector_path, 'r') as f:
        content = f.read()
    
    # Find the location to insert new methods (after the last existing check method)
    # Look for the last check method pattern (check methods have various patterns)
    last_check_pattern = r'(def check_\w+.*?return findings)'
    matches = list(re.finditer(last_check_pattern, content, re.DOTALL))
    
    if not matches:
        print("Error: Could not find existing check methods")
        return
    
    # Get the position after the last check method
    last_match = matches[-1]
    insert_position = last_match.end()
    
    # Generate methods for CHECK-041 to CHECK-060
    new_methods = []
    for i in range(41, 61):
        check_id = f"CHECK-{i:03d}"
        new_methods.append(generate_check_method(check_id))
    
    # Insert the new methods
    new_content = (
        content[:insert_position] + 
        '\n' + '\n'.join(new_methods) + 
        content[insert_position:]
    )
    
    # Write the updated content
    with open(connector_path, 'w') as f:
        f.write(new_content)
    
    print(f"\nAdded {len(new_methods)} new check methods to {connector_path}")
    print(f"Backup saved at: {backup_path}")
    
    # Add import at the top if not already present
    if "from check_implementations_batch1 import Batch1SecurityChecks" not in content:
        print("\nNote: You may need to add the import statement at the top of aws_connector.py:")
        print("from check_implementations_batch1 import Batch1SecurityChecks")


def main():
    """Main function."""
    print("Adding batch 1 check methods to aws_connector.py...")
    add_batch_checks_to_connector()
    print("\nDone! Next steps:")
    print("1. Review the changes in aws_connector.py")
    print("2. Test individual checks")
    print("3. Run the full compliance scan")


if __name__ == "__main__":
    main() 