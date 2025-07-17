#!/usr/bin/env python3
"""Template generator for security check functions."""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime


class CheckTemplate:
    """Templates for different types of security checks."""
    
    @staticmethod
    def basic_resource_check(check_id: str, 
                           service: str,
                           resource_type: str,
                           check_attribute: str,
                           expected_value: Any,
                           region_specific: bool = True) -> str:
        """Generate template for basic resource attribute checks."""
        
        function_name = f"check_{check_id.lower().replace('-', '_')}"
        
        if region_specific:
            template = f'''
    def {function_name}(self) -> List[Dict[str, Any]]:
        """Check {resource_type} for {check_attribute}."""
        findings = []
        
        try:
            # Check all regions
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("{service}", region):
                    continue
                    
                try:
                    client = self.aws.get_client("{service}", region)
                    
                    # TODO: Add pagination if needed
                    response = client.describe_{resource_type}()
                    
                    for resource in response.get('{resource_type.title()}', []):
                        resource_id = resource.get('ResourceId')  # Adjust field name
                        self._track_resource_tested(resource_id)
                        
                        if not resource.get('{check_attribute}', False) == {expected_value}:
                            findings.append({{
                                "type": "{check_id}_VIOLATION",
                                "resource": resource_id,
                                "region": region,
                                "details": f"{{resource_id}} in {{region}} fails {check_attribute} check"
                            }})
                            
                except Exception as e:
                    logger.error(f"Error checking {resource_type} in region {{region}}: {{str(e)}}")
                    
        except Exception as e:
            logger.error(f"Error in {function_name}: {{str(e)}}")
            
        return findings'''
        
        else:
            template = f'''
    def {function_name}(self) -> List[Dict[str, Any]]:
        """Check {resource_type} for {check_attribute}."""
        findings = []
        
        try:
            client = self.aws.get_client("{service}")
            
            # TODO: Add pagination if needed
            response = client.describe_{resource_type}()
            
            for resource in response.get('{resource_type.title()}', []):
                resource_id = resource.get('ResourceId')  # Adjust field name
                self._track_resource_tested(resource_id)
                
                if not resource.get('{check_attribute}', False) == {expected_value}:
                    findings.append({{
                        "type": "{check_id}_VIOLATION",
                        "resource": resource_id,
                        "details": f"{{resource_id}} fails {check_attribute} check"
                    }})
                    
        except Exception as e:
            logger.error(f"Error in {function_name}: {{str(e)}}")
            
        return findings'''
            
        return template
    
    @staticmethod
    def encryption_check(check_id: str,
                        service: str,
                        resource_type: str,
                        encryption_field: str = "Encrypted") -> str:
        """Generate template for encryption checks."""
        
        function_name = f"check_{check_id.lower().replace('-', '_')}"
        
        template = f'''
    def {function_name}(self) -> List[Dict[str, Any]]:
        """Check if {resource_type} are encrypted."""
        findings = []
        
        try:
            for region in self.aws.get_all_regions():
                if not self.aws.check_service_availability("{service}", region):
                    continue
                    
                try:
                    client = self.aws.get_client("{service}", region)
                    
                    # TODO: Add specific API call and pagination
                    resources = []  # Get resources
                    
                    for resource in resources:
                        resource_id = resource.get('ResourceId')  # Adjust field name
                        resource_arn = resource.get('ResourceArn')  # Adjust field name
                        self._track_resource_tested(resource_arn or resource_id)
                        
                        if not resource.get('{encryption_field}', False):
                            findings.append({{
                                "type": "UNENCRYPTED_{resource_type.upper()}",
                                "resource": resource_id,
                                "region": region,
                                "details": f"{{resource_id}} in {{region}} is not encrypted"
                            }})
                            
                except Exception as e:
                    logger.error(f"Error checking {resource_type} encryption in {{region}}: {{str(e)}}")
                    
        except Exception as e:
            logger.error(f"Error in {function_name}: {{str(e)}}")
            
        return findings'''
        
        return template
    
    @staticmethod
    def compliance_check(check_id: str,
                        compliance_type: str,
                        check_logic: str) -> str:
        """Generate template for compliance/configuration checks."""
        
        function_name = f"check_{check_id.lower().replace('-', '_')}"
        
        template = f'''
    def {function_name}(self) -> List[Dict[str, Any]]:
        """Check {compliance_type} compliance."""
        findings = []
        
        try:
            # TODO: Implement specific compliance check logic
            # {check_logic}
            
            # Example structure:
            # 1. Get relevant AWS resources
            # 2. Check compliance criteria
            # 3. Track resources tested
            # 4. Create findings for non-compliant resources
            
            pass  # Replace with actual implementation
                    
        except Exception as e:
            logger.error(f"Error in {function_name}: {{str(e)}}")
            
        return findings'''
        
        return template


class CheckGenerator:
    """Generate security check functions and configurations."""
    
    def __init__(self):
        """Initialize check generator."""
        self.templates = CheckTemplate()
        
    def generate_check_config(self, 
                            check_id: str,
                            name: str,
                            description: str,
                            detailed_description: str,
                            category: str,
                            frameworks: Dict[str, Any],
                            severity: str,
                            nist_mappings: List[str],
                            service: str,
                            remediation: Dict[str, str]) -> Dict[str, Any]:
        """Generate check configuration entry."""
        
        return {
            "id": check_id,
            "name": name,
            "description": description,
            "detailed_description": detailed_description,
            "category": category,
            "frameworks": frameworks,
            "severity": severity,
            "nist_mappings": nist_mappings,
            "service": service,
            "check_function": f"check_{check_id.lower().replace('-', '_')}",
            "remediation": remediation
        }
    
    def generate_batch_checks(self, start_id: int, end_id: int, check_definitions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a batch of checks with configs and functions."""
        
        configs = []
        functions = []
        
        for i, definition in enumerate(check_definitions):
            if i < (end_id - start_id + 1):
                check_id = f"CHECK-{start_id + i:03d}"
                
                # Generate config
                config = self.generate_check_config(
                    check_id=check_id,
                    name=definition['name'],
                    description=definition['description'],
                    detailed_description=definition['detailed_description'],
                    category=definition['category'],
                    frameworks=definition['frameworks'],
                    severity=definition['severity'],
                    nist_mappings=definition['nist_mappings'],
                    service=definition['service'],
                    remediation=definition['remediation']
                )
                configs.append(config)
                
                # Generate function based on type
                check_type = definition.get('type', 'basic')
                
                if check_type == 'encryption':
                    function = self.templates.encryption_check(
                        check_id=check_id,
                        service=definition['service'],
                        resource_type=definition['resource_type'],
                        encryption_field=definition.get('encryption_field', 'Encrypted')
                    )
                elif check_type == 'basic':
                    function = self.templates.basic_resource_check(
                        check_id=check_id,
                        service=definition['service'],
                        resource_type=definition['resource_type'],
                        check_attribute=definition['check_attribute'],
                        expected_value=definition['expected_value'],
                        region_specific=definition.get('region_specific', True)
                    )
                else:  # compliance or custom
                    function = self.templates.compliance_check(
                        check_id=check_id,
                        compliance_type=definition['name'],
                        check_logic=definition.get('check_logic', 'Custom implementation needed')
                    )
                
                functions.append(function)
        
        return {
            'configs': configs,
            'functions': functions
        }


# Import the complete batch 1 definitions
from check_definitions_batch1 import BATCH_1_CHECKS


def main():
    """Generate check configurations and functions."""
    generator = CheckGenerator()
    
    # Generate batch 1
    batch_1 = generator.generate_batch_checks(41, 60, BATCH_1_CHECKS)
    
    # Save configurations
    with open('generated_checks_config.json', 'w') as f:
        json.dump({'security_checks': batch_1['configs']}, f, indent=2)
    
    # Save functions
    with open('generated_check_functions.py', 'w') as f:
        f.write("# Generated check functions\n\n")
        for func in batch_1['functions']:
            f.write(func)
            f.write('\n')
    
    print(f"Generated {len(batch_1['configs'])} check configurations")
    print(f"Generated {len(batch_1['functions'])} check functions")


if __name__ == "__main__":
    main() 