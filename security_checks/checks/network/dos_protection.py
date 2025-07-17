#!/usr/bin/env python3
"""Check for DoS protection mechanisms."""

from typing import Any, Dict, List

from security_checks.base import BaseSecurityCheck


class DoSProtectionCheck(BaseSecurityCheck):
    """Check that AWS Shield and rate limiting are configured."""
    
    @property
    def check_id(self) -> str:
        return "CHECK-075"
    
    @property
    def description(self) -> str:
        return "Enable AWS Shield and rate limiting"
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        return {
            "mitre_attack": ["T1498", "T1499"],
            "nist_800_53": ["SC-5", "SC-6", "CP-2"],
            "nist_800_171": ["3.13.1", "3.12.2"],
            "owasp_cloud": ["OCST-8.1"]
        }
    
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the DoS protection check."""
        # Check Shield Advanced subscription (global)
        self._check_shield_advanced()
        
        for region in self.regions:
            try:
                # Check API Gateway throttling
                self._check_api_gateway_throttling(region)
                
                # Check WAF rate limiting rules
                self._check_waf_rate_limiting(region)
                
                # Check Auto Scaling for resilience
                self._check_auto_scaling(region)
                
            except Exception as e:
                self.handle_error(e, f"checking DoS protection in {region}")
                
        return self.findings
    
    def _check_shield_advanced(self) -> None:
        """Check AWS Shield Advanced subscription."""
        try:
            shield_client = self.aws.get_client('shield', 'us-east-1')
            
            # Check subscription status
            try:
                subscription = shield_client.describe_subscription()
                
                # If we get here, Shield Advanced is enabled
                self.check_metadata['shield_advanced'] = True
                
            except Exception as e:
                if 'ResourceNotFoundException' in str(e):
                    self.add_finding(
                        resource_type="AWS::Shield::Subscription",
                        resource_id="shield-advanced",
                        region="global",
                        severity="MEDIUM",
                        details="AWS Shield Advanced is not enabled",
                        recommendation="Consider enabling AWS Shield Advanced for enhanced DDoS protection and 24/7 DRT support.",
                        evidence={
                            "shield_standard": True,  # Shield Standard is always on
                            "shield_advanced": False
                        }
                    )
                else:
                    raise
                    
        except Exception as e:
            self.handle_error(e, "checking Shield Advanced subscription")
    
    def _check_api_gateway_throttling(self, region: str) -> None:
        """Check API Gateway throttling configuration."""
        try:
            apigateway_client = self.aws.get_client('apigateway', region)
            
            # Get REST APIs
            apis = apigateway_client.get_rest_apis()
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api['name']
                
                # Check stages for throttling settings
                stages = apigateway_client.get_stages(restApiId=api_id)
                
                for stage in stages.get('item', []):
                    stage_name = stage['stageName']
                    
                    # Check throttling settings
                    throttle_settings = stage.get('throttleSettings', {})
                    rate_limit = throttle_settings.get('rateLimit', 0)
                    burst_limit = throttle_settings.get('burstLimit', 0)
                    
                    if rate_limit == 0 or burst_limit == 0:
                        self.add_finding(
                            resource_type="AWS::ApiGateway::Stage",
                            resource_id=f"{api_id}/{stage_name}",
                            region=region,
                            severity="MEDIUM",
                            details=f"API Gateway stage '{stage_name}' does not have throttling configured",
                            recommendation="Configure rate limiting and burst limits to protect against DoS attacks.",
                            evidence={
                                "api_name": api_name,
                                "stage_name": stage_name,
                                "rate_limit": rate_limit,
                                "burst_limit": burst_limit
                            }
                        )
                        
        except Exception as e:
            self.handle_error(e, f"checking API Gateway throttling in {region}")
    
    def _check_waf_rate_limiting(self, region: str) -> None:
        """Check WAF rate limiting rules."""
        try:
            wafv2_client = self.aws.get_client('wafv2', region)
            
            # Check regional and CloudFront WAFs
            for scope in ['REGIONAL', 'CLOUDFRONT']:
                if scope == 'CLOUDFRONT' and region != 'us-east-1':
                    continue
                
                try:
                    web_acls = wafv2_client.list_web_acls(Scope=scope)
                    
                    for web_acl_summary in web_acls.get('WebACLs', []):
                        web_acl_id = web_acl_summary['Id']
                        web_acl_name = web_acl_summary['Name']
                        
                        # Get full WebACL details
                        web_acl = wafv2_client.get_web_acl(
                            Scope=scope,
                            Id=web_acl_id,
                            Name=web_acl_name
                        )
                        
                        # Check for rate-based rules
                        has_rate_rule = False
                        for rule in web_acl['WebACL'].get('Rules', []):
                            if 'RateBasedStatement' in rule.get('Statement', {}):
                                has_rate_rule = True
                                break
                        
                        if not has_rate_rule:
                            self.add_finding(
                                resource_type="AWS::WAFv2::WebACL",
                                resource_id=web_acl_id,
                                region=region if scope == 'REGIONAL' else 'global',
                                severity="MEDIUM",
                                details=f"WAF WebACL '{web_acl_name}' does not have rate-based rules",
                                recommendation="Add rate-based rules to limit requests per IP address.",
                                evidence={
                                    "web_acl_name": web_acl_name,
                                    "scope": scope,
                                    "has_rate_limiting": False
                                }
                            )
                            
                except Exception as e:
                    if 'WAFNonexistentItemException' not in str(e):
                        self.handle_error(e, f"checking WAF rate limiting in {region}")
                        
        except Exception as e:
            self.handle_error(e, f"checking WAF configuration in {region}")
    
    def _check_auto_scaling(self, region: str) -> None:
        """Check Auto Scaling configuration for resilience."""
        try:
            autoscaling_client = self.aws.get_client('autoscaling', region)
            ec2_client = self.aws.get_client('ec2', region)
            
            # Get all running instances
            instances = ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            # Track instances in Auto Scaling groups
            asg_instances = set()
            
            # Get Auto Scaling groups
            asgs = autoscaling_client.describe_auto_scaling_groups()
            
            for asg in asgs.get('AutoScalingGroups', []):
                for instance in asg.get('Instances', []):
                    asg_instances.add(instance['InstanceId'])
            
            # Check for critical instances not in ASGs
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    
                    # Check if instance has production/critical tags
                    is_critical = False
                    for tag in instance.get('Tags', []):
                        if tag['Key'].lower() in ['environment', 'env'] and tag['Value'].lower() in ['production', 'prod']:
                            is_critical = True
                            break
                    
                    if is_critical and instance_id not in asg_instances:
                        self.add_finding(
                            resource_type="AWS::EC2::Instance",
                            resource_id=instance_id,
                            region=region,
                            severity="LOW",
                            details="Critical instance not in Auto Scaling group",
                            recommendation="Add instance to Auto Scaling group for better resilience against DoS attacks.",
                            evidence={
                                "instance_type": instance.get('InstanceType'),
                                "availability_zone": instance.get('Placement', {}).get('AvailabilityZone'),
                                "in_auto_scaling_group": False
                            }
                        )
                        
        except Exception as e:
            self.handle_error(e, f"checking Auto Scaling in {region}")