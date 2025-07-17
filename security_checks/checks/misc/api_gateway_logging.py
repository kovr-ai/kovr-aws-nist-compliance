#!/usr/bin/env python3
"""Ensure API Gateway has logging enabled"""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class ApiGatewayLoggingCheck(BaseSecurityCheck):
    """This check verifies that API Gateway has logging enabled to capture API requests and responses. API logging is essential for monitoring API usage, debugging issues, and detecting potential security threats or abuse. Logs should include access logs and execution logs for comprehensive monitoring."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-037"
    
    @property
    def description(self) -> str:
        return "Ensure API Gateway has logging enabled"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            'nist_800_53': [
                        'AU-2',
                        'AU-3'
            ],
            'nist_800_171': [
                        '3.3.1',
                        '3.3.2'
            ]
}
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the api_gateway_logging check."""
        for region in self.regions:
            try:
                # TODO: Implement check logic for apigateway
                # client = self.aws.get_client('apigateway', region)
                pass
                
            except Exception as e:
                self.handle_error(e, f"checking apigateway in {region}")
                
        return self.findings
