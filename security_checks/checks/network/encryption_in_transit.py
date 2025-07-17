#!/usr/bin/env python3
"""Check for encryption in transit across services."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class NetworkEncryptionCheck(BaseSecurityCheck):
    """Check that all data in transit is encrypted."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-073"
    
    @property
    def description(self) -> str:
        return "Ensure encryption for all data in transit"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "mitre_attack": ["T1040", "T1557"],
            "nist_800_53": ["SC-8", "SC-13", "SC-23"],
            "nist_800_171": ["3.13.8", "3.13.10"],
            "pci_dss": ["4.1"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the network encryption check."""
        for region in self.regions:
            try:
                # Check ELB listeners
                self._check_elb_encryption(region)
                
                # Check API Gateway encryption
                self._check_api_gateway_encryption(region)
                
                # Check CloudFront distributions
                if region == 'us-east-1':  # CloudFront is global
                    self._check_cloudfront_encryption()
                    
            except Exception as e:
                self.handle_error(e, f"checking encryption in transit in {region}")
                
        return self.findings
    
    def _check_elb_encryption(self, region: str) -> None:
        """Check ELB listener encryption."""
        try:
            # Check ALB/NLB
            elbv2_client = self.aws.get_client('elbv2', region)
            
            paginator = elbv2_client.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    lb_arn = lb['LoadBalancerArn']
                    lb_name = lb['LoadBalancerName']
                    
                    # Get listeners
                    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                    
                    for listener in listeners.get('Listeners', []):
                        protocol = listener.get('Protocol')
                        port = listener.get('Port')
                        
                        # Check for unencrypted protocols
                        if protocol in ['HTTP', 'TCP'] and port not in [80]:  # Port 80 redirect is common
                            # Check if it's redirecting to HTTPS
                            is_redirect = False
                            for action in listener.get('DefaultActions', []):
                                if action.get('Type') == 'redirect':
                                    redirect_config = action.get('RedirectConfig', {})
                                    if redirect_config.get('Protocol') == 'HTTPS':
                                        is_redirect = True
                                        break
                            
                            if not is_redirect:
                                self.add_finding(
                                    resource_type="AWS::ElasticLoadBalancingV2::Listener",
                                    resource_id=listener['ListenerArn'],
                                    region=region,
                                    severity="HIGH",
                                    details=f"Load balancer listener uses unencrypted {protocol} protocol",
                                    recommendation="Configure the listener to use HTTPS/TLS for encrypted communication.",
                                    evidence={
                                        "load_balancer": lb_name,
                                        "protocol": protocol,
                                        "port": port,
                                        "ssl_policy": listener.get('SslPolicy')
                                    }
                                )
                                
        except Exception as e:
            self.handle_error(e, f"checking ELB encryption in {region}")
    
    def _check_api_gateway_encryption(self, region: str) -> None:
        """Check API Gateway encryption settings."""
        try:
            apigateway_client = self.aws.get_client('apigateway', region)
            
            # Check REST APIs
            apis = apigateway_client.get_rest_apis()
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api['name']
                
                # Check if API enforces TLS
                if api.get('minimumCompressionSize') is None:
                    # Get stages
                    stages = apigateway_client.get_stages(restApiId=api_id)
                    
                    for stage in stages.get('item', []):
                        method_settings = stage.get('methodSettings', {})
                        
                        # Check if TLS is enforced
                        tls_enforced = any(
                            settings.get('requireHttps', False)
                            for settings in method_settings.values()
                        )
                        
                        if not tls_enforced and not stage.get('clientCertificateId'):
                            self.add_finding(
                                resource_type="AWS::ApiGateway::Stage",
                                resource_id=f"{api_id}/{stage['stageName']}",
                                region=region,
                                severity="HIGH",
                                details=f"API Gateway stage does not enforce TLS/HTTPS",
                                recommendation="Configure the API Gateway to require HTTPS for all methods.",
                                evidence={
                                    "api_name": api_name,
                                    "stage_name": stage['stageName'],
                                    "deployment_id": stage.get('deploymentId')
                                }
                            )
                            
        except Exception as e:
            self.handle_error(e, f"checking API Gateway encryption in {region}")
    
    def _check_cloudfront_encryption(self) -> None:
        """Check CloudFront distribution encryption."""
        try:
            cloudfront_client = self.aws.get_client('cloudfront', 'us-east-1')
            
            # List distributions
            distributions = cloudfront_client.list_distributions()
            
            for dist_summary in distributions.get('DistributionList', {}).get('Items', []):
                dist_id = dist_summary['Id']
                
                # Get full distribution config
                dist_config = cloudfront_client.get_distribution_config(Id=dist_id)
                config = dist_config['DistributionConfig']
                
                # Check viewer protocol policy
                default_behavior = config.get('DefaultCacheBehavior', {})
                viewer_protocol = default_behavior.get('ViewerProtocolPolicy')
                
                if viewer_protocol == 'allow-all':
                    self.add_finding(
                        resource_type="AWS::CloudFront::Distribution",
                        resource_id=dist_id,
                        region="global",
                        severity="HIGH",
                        details="CloudFront distribution allows unencrypted HTTP connections",
                        recommendation="Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only'.",
                        evidence={
                            "domain_name": dist_summary.get('DomainName'),
                            "viewer_protocol_policy": viewer_protocol,
                            "minimum_protocol_version": default_behavior.get('MinimumProtocolVersion')
                        }
                    )
                    
        except Exception as e:
            self.handle_error(e, "checking CloudFront encryption")