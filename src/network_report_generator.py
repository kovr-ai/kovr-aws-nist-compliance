#!/usr/bin/env python3
"""Network resources report generator for AWS infrastructure."""

import csv
import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class NetworkReportGenerator:
    """Generates comprehensive network infrastructure reports."""
    
    def __init__(self, aws_connector):
        """Initialize network report generator.
        
        Args:
            aws_connector: AWSConnector instance for accessing AWS services
        """
        self.aws = aws_connector
        self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.account_id = aws_connector.account_id
        
    def generate_network_report(self, output_dir: str, regions: Optional[List[str]] = None) -> str:
        """Generate comprehensive network infrastructure report.
        
        Args:
            output_dir: Output directory for reports
            regions: List of regions to check. If None, will use all regions.
                    If empty list, will only check the default region.
            
        Returns:
            Path to the generated report file
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Respect the user's region choice - only use all regions if explicitly None
        if regions is None:
            # None means not specified - default to all regions
            logger.info("No regions specified, using all available regions")
            regions = self.aws.get_all_regions()
        elif not regions:
            # Empty list - this shouldn't happen if user specified a region
            # But if it does, use the default region from the AWS connector
            logger.warning(f"Empty regions list provided, using default region: {self.aws.region}")
            regions = [self.aws.region]
        else:
            # User specified regions - use exactly those
            logger.info(f"Generating network report for specified regions: {', '.join(regions)}")
        
        # Collect network data from specified regions
        network_data = self._collect_network_data(regions)
        
        # Generate markdown report
        md_path = self._generate_markdown_report(network_data, output_dir)
        
        # Generate CSV report
        csv_path = self._generate_csv_report(network_data, output_dir)
        
        # Generate JSON report
        json_path = self._generate_json_report(network_data, output_dir)
        
        logger.info(f"Network report generated: {md_path}")
        logger.info(f"Network CSV report generated: {csv_path}")
        logger.info(f"Network JSON report generated: {json_path}")
        
        return md_path
    
    def _collect_network_data(self, regions: List[str]) -> Dict[str, Any]:
        """Collect network data from all regions.
        
        Args:
            regions: List of regions to check
            
        Returns:
            Dictionary containing all network resources organized by type
        """
        network_data = {
            "vpcs": [],
            "subnets": [],
            "network_acls": [],
            "security_groups": [],
            "vpc_endpoints": [],
            "internet_gateways": [],
            "route_tables": [],
            "network_interfaces": [],
            "load_balancers": [],
            "nat_gateways": [],
            "vpn_gateways": [],
            "transit_gateways": [],
            "direct_connect": [],
            "peering_connections": [],
            "metadata": {
                "account_id": self.account_id,
                "timestamp": datetime.utcnow().isoformat(),
                "regions_checked": regions
            }
        }
        
        for region in regions:
            try:
                logger.info(f"Collecting network data from {region}...")
                
                # Collect VPCs
                network_data["vpcs"].extend(self._collect_vpcs(region))
                
                # Collect Subnets
                network_data["subnets"].extend(self._collect_subnets(region))
                
                # Collect Network ACLs
                network_data["network_acls"].extend(self._collect_network_acls(region))
                
                # Collect Security Groups
                network_data["security_groups"].extend(self._collect_security_groups(region))
                
                # Collect VPC Endpoints
                network_data["vpc_endpoints"].extend(self._collect_vpc_endpoints(region))
                
                # Collect Internet Gateways
                network_data["internet_gateways"].extend(self._collect_internet_gateways(region))
                
                # Collect Route Tables
                network_data["route_tables"].extend(self._collect_route_tables(region))
                
                # Collect Network Interfaces
                network_data["network_interfaces"].extend(self._collect_network_interfaces(region))
                
                # Collect Load Balancers
                network_data["load_balancers"].extend(self._collect_load_balancers(region))
                
                # Collect NAT Gateways
                network_data["nat_gateways"].extend(self._collect_nat_gateways(region))
                
                # Collect VPN Gateways
                network_data["vpn_gateways"].extend(self._collect_vpn_gateways(region))
                
                # Collect Transit Gateways
                network_data["transit_gateways"].extend(self._collect_transit_gateways(region))
                
                # Collect VPC Peering Connections
                network_data["peering_connections"].extend(self._collect_peering_connections(region))
                
            except Exception as e:
                logger.error(f"Error collecting network data from {region}: {str(e)}")
                continue
        
        return network_data
    
    def _collect_vpcs(self, region: str) -> List[Dict[str, Any]]:
        """Collect VPC information."""
        vpcs = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_vpcs()
            
            for vpc in response.get("Vpcs", []):
                vpc_data = {
                    "vpc_id": vpc.get("VpcId"),
                    "cidr_block": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "is_default": vpc.get("IsDefault", False),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in vpc.get("Tags", [])},
                    "cidr_blocks": [vpc.get("CidrBlock")] + [cb["CidrBlock"] for cb in vpc.get("CidrBlockAssociationSet", [])],
                    "ipv6_cidr_blocks": [cb["Ipv6CidrBlock"] for cb in vpc.get("Ipv6CidrBlockAssociationSet", [])],
                    "dhcp_options_id": vpc.get("DhcpOptionsId"),
                    "instance_tenancy": vpc.get("InstanceTenancy", "default")
                }
                vpcs.append(vpc_data)
        except Exception as e:
            logger.error(f"Error collecting VPCs from {region}: {str(e)}")
        
        return vpcs
    
    def _collect_subnets(self, region: str) -> List[Dict[str, Any]]:
        """Collect Subnet information."""
        subnets = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_subnets()
            
            for subnet in response.get("Subnets", []):
                subnet_data = {
                    "subnet_id": subnet.get("SubnetId"),
                    "vpc_id": subnet.get("VpcId"),
                    "cidr_block": subnet.get("CidrBlock"),
                    "availability_zone": subnet.get("AvailabilityZone"),
                    "state": subnet.get("State"),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in subnet.get("Tags", [])},
                    "available_ip_address_count": subnet.get("AvailableIpAddressCount"),
                    "ipv6_cidr_blocks": [cb["Ipv6CidrBlock"] for cb in subnet.get("Ipv6CidrBlockAssociationSet", [])],
                    "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                    "assign_ipv6_address_on_creation": subnet.get("AssignIpv6AddressOnCreation", False)
                }
                subnets.append(subnet_data)
        except Exception as e:
            logger.error(f"Error collecting subnets from {region}: {str(e)}")
        
        return subnets
    
    def _collect_network_acls(self, region: str) -> List[Dict[str, Any]]:
        """Collect Network ACL information."""
        nacls = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_network_acls()
            
            for nacl in response.get("NetworkAcls", []):
                # Process ingress rules
                ingress_rules = []
                for entry in nacl.get("Entries", []):
                    if not entry.get("Egress", False):  # Ingress rule
                        ingress_rules.append({
                            "rule_number": entry.get("RuleNumber"),
                            "protocol": entry.get("Protocol"),
                            "port_range": f"{entry.get('PortRange', {}).get('From', 'N/A')}-{entry.get('PortRange', {}).get('To', 'N/A')}",
                            "cidr_block": entry.get("CidrBlock"),
                            "rule_action": entry.get("RuleAction"),
                            "icmp_type_code": entry.get("IcmpTypeCode", {})
                        })
                
                # Process egress rules
                egress_rules = []
                for entry in nacl.get("Entries", []):
                    if entry.get("Egress", False):  # Egress rule
                        egress_rules.append({
                            "rule_number": entry.get("RuleNumber"),
                            "protocol": entry.get("Protocol"),
                            "port_range": f"{entry.get('PortRange', {}).get('From', 'N/A')}-{entry.get('PortRange', {}).get('To', 'N/A')}",
                            "cidr_block": entry.get("CidrBlock"),
                            "rule_action": entry.get("RuleAction"),
                            "icmp_type_code": entry.get("IcmpTypeCode", {})
                        })
                
                nacl_data = {
                    "network_acl_id": nacl.get("NetworkAclId"),
                    "vpc_id": nacl.get("VpcId"),
                    "is_default": nacl.get("IsDefault", False),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in nacl.get("Tags", [])},
                    "ingress_rules": ingress_rules,
                    "egress_rules": egress_rules,
                    "associations": [assoc.get("SubnetId") for assoc in nacl.get("Associations", [])]
                }
                nacls.append(nacl_data)
        except Exception as e:
            logger.error(f"Error collecting Network ACLs from {region}: {str(e)}")
        
        return nacls
    
    def _collect_security_groups(self, region: str) -> List[Dict[str, Any]]:
        """Collect Security Group information."""
        security_groups = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_security_groups()
            
            for sg in response.get("SecurityGroups", []):
                # Process ingress rules
                ingress_rules = []
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        ingress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "source": ip_range.get("CidrIp", "N/A"),
                            "description": ip_range.get("Description", ""),
                            "source_type": "CIDR"
                        })
                    for ipv6_range in rule.get("Ipv6Ranges", []):
                        ingress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "source": ipv6_range.get("CidrIpv6", "N/A"),
                            "description": ipv6_range.get("Description", ""),
                            "source_type": "IPv6"
                        })
                    for user_id_group in rule.get("UserIdGroupPairs", []):
                        ingress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "source": user_id_group.get("GroupId", "N/A"),
                            "description": user_id_group.get("Description", ""),
                            "source_type": "Security Group"
                        })
                
                # Process egress rules
                egress_rules = []
                for rule in sg.get("IpPermissionsEgress", []):
                    for ip_range in rule.get("IpRanges", []):
                        egress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "destination": ip_range.get("CidrIp", "N/A"),
                            "description": ip_range.get("Description", ""),
                            "destination_type": "CIDR"
                        })
                    for ipv6_range in rule.get("Ipv6Ranges", []):
                        egress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "destination": ipv6_range.get("CidrIpv6", "N/A"),
                            "description": ipv6_range.get("Description", ""),
                            "destination_type": "IPv6"
                        })
                    for user_id_group in rule.get("UserIdGroupPairs", []):
                        egress_rules.append({
                            "protocol": rule.get("IpProtocol", "-1"),
                            "port_range": self._format_port_range(rule),
                            "destination": user_id_group.get("GroupId", "N/A"),
                            "description": user_id_group.get("Description", ""),
                            "destination_type": "Security Group"
                        })
                
                sg_data = {
                    "group_id": sg.get("GroupId"),
                    "group_name": sg.get("GroupName"),
                    "description": sg.get("Description", ""),
                    "vpc_id": sg.get("VpcId"),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])},
                    "ingress_rules": ingress_rules,
                    "egress_rules": egress_rules,
                    "ingress_rule_count": len(ingress_rules),
                    "egress_rule_count": len(egress_rules)
                }
                security_groups.append(sg_data)
        except Exception as e:
            logger.error(f"Error collecting Security Groups from {region}: {str(e)}")
        
        return security_groups
    
    def _format_port_range(self, rule: Dict[str, Any]) -> str:
        """Format port range from rule."""
        if rule.get("FromPort") == rule.get("ToPort"):
            if rule.get("FromPort") is None:
                return "All"
            return str(rule.get("FromPort"))
        return f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}"
    
    def _collect_vpc_endpoints(self, region: str) -> List[Dict[str, Any]]:
        """Collect VPC Endpoint information."""
        endpoints = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_vpc_endpoints()
            
            for endpoint in response.get("VpcEndpoints", []):
                endpoint_data = {
                    "vpc_endpoint_id": endpoint.get("VpcEndpointId"),
                    "vpc_id": endpoint.get("VpcId"),
                    "service_name": endpoint.get("ServiceName"),
                    "state": endpoint.get("State"),
                    "vpc_endpoint_type": endpoint.get("VpcEndpointType"),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in endpoint.get("Tags", [])},
                    "subnet_ids": endpoint.get("SubnetIds", []),
                    "security_group_ids": endpoint.get("Groups", []),
                    "policy_document": endpoint.get("PolicyDocument"),
                    "private_dns_enabled": endpoint.get("PrivateDnsEnabled", False)
                }
                endpoints.append(endpoint_data)
        except Exception as e:
            logger.error(f"Error collecting VPC Endpoints from {region}: {str(e)}")
        
        return endpoints
    
    def _collect_internet_gateways(self, region: str) -> List[Dict[str, Any]]:
        """Collect Internet Gateway information."""
        igws = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_internet_gateways()
            
            for igw in response.get("InternetGateways", []):
                igw_data = {
                    "internet_gateway_id": igw.get("InternetGatewayId"),
                    "state": "attached" if igw.get("Attachments") else "detached",
                    "vpc_id": igw.get("Attachments", [{}])[0].get("VpcId") if igw.get("Attachments") else None,
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in igw.get("Tags", [])}
                }
                igws.append(igw_data)
        except Exception as e:
            logger.error(f"Error collecting Internet Gateways from {region}: {str(e)}")
        
        return igws
    
    def _collect_route_tables(self, region: str) -> List[Dict[str, Any]]:
        """Collect Route Table information."""
        route_tables = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_route_tables()
            
            for rt in response.get("RouteTables", []):
                routes = []
                for route in rt.get("Routes", []):
                    routes.append({
                        "destination_cidr_block": route.get("DestinationCidrBlock"),
                        "destination_ipv6_cidr_block": route.get("DestinationIpv6CidrBlock"),
                        "gateway_id": route.get("GatewayId"),
                        "instance_id": route.get("InstanceId"),
                        "nat_gateway_id": route.get("NatGatewayId"),
                        "transit_gateway_id": route.get("TransitGatewayId"),
                        "vpc_peering_connection_id": route.get("VpcPeeringConnectionId"),
                        "network_interface_id": route.get("NetworkInterfaceId"),
                        "state": route.get("State")
                    })
                
                route_table_data = {
                    "route_table_id": rt.get("RouteTableId"),
                    "vpc_id": rt.get("VpcId"),
                    "is_main": rt.get("Associations", [{}])[0].get("Main", False) if rt.get("Associations") else False,
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in rt.get("Tags", [])},
                    "routes": routes,
                    "associations": [assoc.get("SubnetId") for assoc in rt.get("Associations", []) if assoc.get("SubnetId")]
                }
                route_tables.append(route_table_data)
        except Exception as e:
            logger.error(f"Error collecting Route Tables from {region}: {str(e)}")
        
        return route_tables
    
    def _collect_network_interfaces(self, region: str) -> List[Dict[str, Any]]:
        """Collect Network Interface information."""
        network_interfaces = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_network_interfaces()
            
            for eni in response.get("NetworkInterfaces", []):
                eni_data = {
                    "network_interface_id": eni.get("NetworkInterfaceId"),
                    "subnet_id": eni.get("SubnetId"),
                    "vpc_id": eni.get("VpcId"),
                    "availability_zone": eni.get("AvailabilityZone"),
                    "description": eni.get("Description", ""),
                    "status": eni.get("Status"),
                    "private_ip_address": eni.get("PrivateIpAddress"),
                    "private_ip_addresses": [ip.get("PrivateIpAddress") for ip in eni.get("PrivateIpAddresses", [])],
                    "public_ip": eni.get("Association", {}).get("PublicIp") if eni.get("Association") else None,
                    "security_groups": [sg.get("GroupId") for sg in eni.get("Groups", [])],
                    "attachment": {
                        "instance_id": eni.get("Attachment", {}).get("InstanceId") if eni.get("Attachment") else None,
                        "device_index": eni.get("Attachment", {}).get("DeviceIndex") if eni.get("Attachment") else None,
                        "status": eni.get("Attachment", {}).get("Status") if eni.get("Attachment") else None
                    },
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in eni.get("Tags", [])},
                    "interface_type": eni.get("InterfaceType", "interface")
                }
                network_interfaces.append(eni_data)
        except Exception as e:
            logger.error(f"Error collecting Network Interfaces from {region}: {str(e)}")
        
        return network_interfaces
    
    def _collect_load_balancers(self, region: str) -> List[Dict[str, Any]]:
        """Collect Load Balancer information (ALB, NLB, CLB)."""
        load_balancers = []
        
        # Application Load Balancers and Network Load Balancers
        try:
            elbv2 = self.aws.get_client("elbv2", region)
            response = elbv2.describe_load_balancers()
            
            for lb in response.get("LoadBalancers", []):
                # Get listeners
                listeners = []
                try:
                    listeners_response = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])
                    for listener in listeners_response.get("Listeners", []):
                        listeners.append({
                            "listener_arn": listener.get("ListenerArn"),
                            "port": listener.get("Port"),
                            "protocol": listener.get("Protocol"),
                            "ssl_policy": listener.get("SslPolicy", ""),
                            "certificates": [cert.get("CertificateArn") for cert in listener.get("Certificates", [])]
                        })
                except Exception as e:
                    logger.warning(f"Error getting listeners for {lb.get('LoadBalancerArn')}: {str(e)}")
                
                lb_data = {
                    "load_balancer_arn": lb.get("LoadBalancerArn"),
                    "load_balancer_name": lb.get("LoadBalancerName"),
                    "type": lb.get("Type"),  # application or network
                    "scheme": lb.get("Scheme"),  # internet-facing or internal
                    "state": lb.get("State", {}).get("Code"),
                    "vpc_id": lb.get("VpcId"),
                    "subnets": lb.get("AvailabilityZones", []),
                    "security_groups": lb.get("SecurityGroups", []),
                    "ip_address_type": lb.get("IpAddressType"),
                    "region": region,
                    "tags": {},
                    "listeners": listeners
                }
                
                # Get tags
                try:
                    tags_response = elbv2.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])
                    if tags_response.get("TagDescriptions"):
                        lb_data["tags"] = {tag["Key"]: tag["Value"] for tag in tags_response["TagDescriptions"][0].get("Tags", [])}
                except Exception as e:
                    logger.warning(f"Error getting tags for {lb.get('LoadBalancerArn')}: {str(e)}")
                
                load_balancers.append(lb_data)
        except Exception as e:
            logger.error(f"Error collecting ALB/NLB from {region}: {str(e)}")
        
        # Classic Load Balancers
        try:
            elb = self.aws.get_client("elb", region)
            response = elb.describe_load_balancers()
            
            for lb in response.get("LoadBalancerDescriptions", []):
                lb_data = {
                    "load_balancer_name": lb.get("LoadBalancerName"),
                    "dns_name": lb.get("DNSName"),
                    "type": "classic",
                    "scheme": lb.get("Scheme"),
                    "vpc_id": lb.get("VPCId"),
                    "subnets": lb.get("Subnets", []),
                    "security_groups": lb.get("SecurityGroups", []),
                    "listeners": [{
                        "protocol": l.get("Protocol"),
                        "load_balancer_port": l.get("LoadBalancerPort"),
                        "instance_protocol": l.get("InstanceProtocol"),
                        "instance_port": l.get("InstancePort"),
                        "ssl_certificate_id": l.get("SSLCertificateId", "")
                    } for l in lb.get("ListenerDescriptions", [])],
                    "region": region,
                    "tags": {}
                }
                load_balancers.append(lb_data)
        except Exception as e:
            logger.error(f"Error collecting Classic Load Balancers from {region}: {str(e)}")
        
        return load_balancers
    
    def _collect_nat_gateways(self, region: str) -> List[Dict[str, Any]]:
        """Collect NAT Gateway information."""
        nat_gateways = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_nat_gateways()
            
            for nat in response.get("NatGateways", []):
                nat_data = {
                    "nat_gateway_id": nat.get("NatGatewayId"),
                    "subnet_id": nat.get("SubnetId"),
                    "vpc_id": nat.get("VpcId"),
                    "state": nat.get("State"),
                    "public_ip": nat.get("NatGatewayAddresses", [{}])[0].get("PublicIp") if nat.get("NatGatewayAddresses") else None,
                    "private_ip": nat.get("NatGatewayAddresses", [{}])[0].get("PrivateIp") if nat.get("NatGatewayAddresses") else None,
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in nat.get("Tags", [])},
                    "create_time": nat.get("CreateTime").isoformat() if nat.get("CreateTime") else None
                }
                nat_gateways.append(nat_data)
        except Exception as e:
            logger.error(f"Error collecting NAT Gateways from {region}: {str(e)}")
        
        return nat_gateways
    
    def _collect_vpn_gateways(self, region: str) -> List[Dict[str, Any]]:
        """Collect VPN Gateway information."""
        vpn_gateways = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_vpn_gateways()
            
            for vpn in response.get("VpnGateways", []):
                vpn_data = {
                    "vpn_gateway_id": vpn.get("VpnGatewayId"),
                    "state": vpn.get("State"),
                    "type": vpn.get("Type"),
                    "vpc_attachments": [att.get("VpcId") for att in vpn.get("VpcAttachments", [])],
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in vpn.get("Tags", [])}
                }
                vpn_gateways.append(vpn_data)
        except Exception as e:
            logger.error(f"Error collecting VPN Gateways from {region}: {str(e)}")
        
        return vpn_gateways
    
    def _collect_transit_gateways(self, region: str) -> List[Dict[str, Any]]:
        """Collect Transit Gateway information."""
        transit_gateways = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_transit_gateways()
            
            for tgw in response.get("TransitGateways", []):
                tgw_data = {
                    "transit_gateway_id": tgw.get("TransitGatewayId"),
                    "state": tgw.get("State"),
                    "amazon_side_asn": tgw.get("Options", {}).get("AmazonSideAsn"),
                    "auto_accept_shared_attachments": tgw.get("Options", {}).get("AutoAcceptSharedAttachments"),
                    "default_route_table_association": tgw.get("Options", {}).get("DefaultRouteTableAssociation"),
                    "default_route_table_propagation": tgw.get("Options", {}).get("DefaultRouteTablePropagation"),
                    "dns_support": tgw.get("Options", {}).get("DnsSupport"),
                    "vpn_ecmp_support": tgw.get("Options", {}).get("VpnEcmpSupport"),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in tgw.get("Tags", [])}
                }
                transit_gateways.append(tgw_data)
        except Exception as e:
            logger.error(f"Error collecting Transit Gateways from {region}: {str(e)}")
        
        return transit_gateways
    
    def _collect_peering_connections(self, region: str) -> List[Dict[str, Any]]:
        """Collect VPC Peering Connection information."""
        peering_connections = []
        try:
            ec2 = self.aws.get_client("ec2", region)
            response = ec2.describe_vpc_peering_connections()
            
            for pcx in response.get("VpcPeeringConnections", []):
                pcx_data = {
                    "vpc_peering_connection_id": pcx.get("VpcPeeringConnectionId"),
                    "status": pcx.get("Status", {}).get("Code"),
                    "requester_vpc_id": pcx.get("RequesterVpcInfo", {}).get("VpcId"),
                    "accepter_vpc_id": pcx.get("AccepterVpcInfo", {}).get("VpcId"),
                    "requester_cidr": pcx.get("RequesterVpcInfo", {}).get("CidrBlock"),
                    "accepter_cidr": pcx.get("AccepterVpcInfo", {}).get("CidrBlock"),
                    "region": region,
                    "tags": {tag["Key"]: tag["Value"] for tag in pcx.get("Tags", [])}
                }
                peering_connections.append(pcx_data)
        except Exception as e:
            logger.error(f"Error collecting VPC Peering Connections from {region}: {str(e)}")
        
        return peering_connections
    
    def _generate_markdown_report(self, network_data: Dict[str, Any], output_dir: str) -> str:
        """Generate markdown network report."""
        file_path = os.path.join(output_dir, f"network_infrastructure_report_{self.timestamp}.md")
        
        with open(file_path, "w", encoding="utf-8") as f:
            # Header
            f.write("# AWS Network Infrastructure Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Account ID:** {network_data['metadata']['account_id']}\n")
            f.write(f"**Regions Checked:** {', '.join(network_data['metadata']['regions_checked'])}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total VPCs:** {len(network_data['vpcs'])}\n")
            f.write(f"- **Total Subnets:** {len(network_data['subnets'])}\n")
            f.write(f"- **Total Security Groups:** {len(network_data['security_groups'])}\n")
            f.write(f"- **Total Network ACLs:** {len(network_data['network_acls'])}\n")
            f.write(f"- **Total VPC Endpoints:** {len(network_data['vpc_endpoints'])}\n")
            f.write(f"- **Total Internet Gateways:** {len(network_data['internet_gateways'])}\n")
            f.write(f"- **Total Route Tables:** {len(network_data['route_tables'])}\n")
            f.write(f"- **Total Network Interfaces:** {len(network_data['network_interfaces'])}\n")
            f.write(f"- **Total Load Balancers:** {len(network_data['load_balancers'])}\n")
            f.write(f"- **Total NAT Gateways:** {len(network_data['nat_gateways'])}\n")
            f.write(f"- **Total VPN Gateways:** {len(network_data['vpn_gateways'])}\n")
            f.write(f"- **Total Transit Gateways:** {len(network_data['transit_gateways'])}\n")
            f.write(f"- **Total VPC Peering Connections:** {len(network_data['peering_connections'])}\n\n")
            
            # VPCs Section
            f.write("## VPCs\n\n")
            if network_data['vpcs']:
                f.write("| VPC ID | CIDR Block | State | Default | Region | Tags |\n")
                f.write("|--------|------------|-------|---------|--------|------|\n")
                for vpc in network_data['vpcs']:
                    tags_str = ", ".join([f"{k}={v}" for k, v in vpc.get('tags', {}).items()])[:50]
                    f.write(f"| {vpc['vpc_id']} | {vpc['cidr_block']} | {vpc['state']} | {vpc['is_default']} | {vpc['region']} | {tags_str} |\n")
            else:
                f.write("No VPCs found.\n")
            f.write("\n")
            
            # Subnets Section
            f.write("## Subnets\n\n")
            if network_data['subnets']:
                f.write("| Subnet ID | VPC ID | CIDR Block | AZ | State | Public IP | Region |\n")
                f.write("|-----------|--------|------------|----|-------|-----------|--------|\n")
                for subnet in network_data['subnets']:
                    f.write(f"| {subnet['subnet_id']} | {subnet['vpc_id']} | {subnet['cidr_block']} | {subnet['availability_zone']} | {subnet['state']} | {subnet['map_public_ip_on_launch']} | {subnet['region']} |\n")
            else:
                f.write("No subnets found.\n")
            f.write("\n")
            
            # Security Groups Section
            f.write("## Security Groups\n\n")
            if network_data['security_groups']:
                for sg in network_data['security_groups']:
                    f.write(f"### {sg['group_name']} ({sg['group_id']})\n\n")
                    f.write(f"- **VPC:** {sg.get('vpc_id', 'N/A')}\n")
                    f.write(f"- **Description:** {sg.get('description', 'N/A')}\n")
                    f.write(f"- **Region:** {sg['region']}\n")
                    f.write(f"- **Ingress Rules:** {sg['ingress_rule_count']}\n")
                    f.write(f"- **Egress Rules:** {sg['egress_rule_count']}\n\n")
                    
                    if sg['ingress_rules']:
                        f.write("**Ingress Rules:**\n")
                        f.write("| Protocol | Port Range | Source | Type |\n")
                        f.write("|----------|------------|--------|------|\n")
                        for rule in sg['ingress_rules'][:10]:  # Limit to first 10
                            f.write(f"| {rule['protocol']} | {rule['port_range']} | {rule['source']} | {rule['source_type']} |\n")
                        if len(sg['ingress_rules']) > 10:
                            f.write(f"*... and {len(sg['ingress_rules']) - 10} more ingress rules*\n")
                        f.write("\n")
                    
                    if sg['egress_rules']:
                        f.write("**Egress Rules:**\n")
                        f.write("| Protocol | Port Range | Destination | Type |\n")
                        f.write("|----------|------------|-------------|------|\n")
                        for rule in sg['egress_rules'][:10]:  # Limit to first 10
                            f.write(f"| {rule['protocol']} | {rule['port_range']} | {rule['destination']} | {rule['destination_type']} |\n")
                        if len(sg['egress_rules']) > 10:
                            f.write(f"*... and {len(sg['egress_rules']) - 10} more egress rules*\n")
                        f.write("\n")
            else:
                f.write("No security groups found.\n")
            f.write("\n")
            
            # Network ACLs Section
            f.write("## Network ACLs\n\n")
            if network_data['network_acls']:
                for nacl in network_data['network_acls']:
                    f.write(f"### {nacl['network_acl_id']}\n\n")
                    f.write(f"- **VPC:** {nacl.get('vpc_id', 'N/A')}\n")
                    f.write(f"- **Default:** {nacl['is_default']}\n")
                    f.write(f"- **Region:** {nacl['region']}\n")
                    f.write(f"- **Associated Subnets:** {', '.join(nacl.get('associations', []))}\n\n")
                    
                    if nacl['ingress_rules']:
                        f.write("**Ingress Rules:**\n")
                        f.write("| Rule # | Protocol | Port Range | CIDR | Action |\n")
                        f.write("|--------|----------|------------|------|--------|\n")
                        for rule in nacl['ingress_rules'][:10]:
                            f.write(f"| {rule['rule_number']} | {rule['protocol']} | {rule['port_range']} | {rule['cidr_block']} | {rule['rule_action']} |\n")
                        if len(nacl['ingress_rules']) > 10:
                            f.write(f"*... and {len(nacl['ingress_rules']) - 10} more ingress rules*\n")
                        f.write("\n")
                    
                    if nacl['egress_rules']:
                        f.write("**Egress Rules:**\n")
                        f.write("| Rule # | Protocol | Port Range | CIDR | Action |\n")
                        f.write("|--------|----------|------------|------|--------|\n")
                        for rule in nacl['egress_rules'][:10]:
                            f.write(f"| {rule['rule_number']} | {rule['protocol']} | {rule['port_range']} | {rule['cidr_block']} | {rule['rule_action']} |\n")
                        if len(nacl['egress_rules']) > 10:
                            f.write(f"*... and {len(nacl['egress_rules']) - 10} more egress rules*\n")
                        f.write("\n")
            else:
                f.write("No Network ACLs found.\n")
            f.write("\n")
            
            # VPC Endpoints Section
            f.write("## VPC Endpoints\n\n")
            if network_data['vpc_endpoints']:
                f.write("| Endpoint ID | Service | Type | State | VPC | Region |\n")
                f.write("|-------------|--------|------|-------|-----|--------|\n")
                for endpoint in network_data['vpc_endpoints']:
                    f.write(f"| {endpoint['vpc_endpoint_id']} | {endpoint['service_name']} | {endpoint['vpc_endpoint_type']} | {endpoint['state']} | {endpoint['vpc_id']} | {endpoint['region']} |\n")
            else:
                f.write("No VPC Endpoints found.\n")
            f.write("\n")
            
            # Load Balancers Section
            f.write("## Load Balancers\n\n")
            if network_data['load_balancers']:
                f.write("| Name | Type | Scheme | State | VPC | Region | Listeners |\n")
                f.write("|------|------|--------|-------|-----|--------|-----------|\n")
                for lb in network_data['load_balancers']:
                    name = lb.get('load_balancer_name') or lb.get('load_balancer_arn', 'N/A')
                    listener_count = len(lb.get('listeners', []))
                    f.write(f"| {name} | {lb['type']} | {lb.get('scheme', 'N/A')} | {lb.get('state', 'N/A')} | {lb.get('vpc_id', 'N/A')} | {lb['region']} | {listener_count} |\n")
            else:
                f.write("No Load Balancers found.\n")
            f.write("\n")
            
            # Additional sections for other resources
            f.write("## Internet Gateways\n\n")
            if network_data['internet_gateways']:
                f.write("| IGW ID | VPC ID | State | Region |\n")
                f.write("|--------|--------|-------|--------|\n")
                for igw in network_data['internet_gateways']:
                    f.write(f"| {igw['internet_gateway_id']} | {igw.get('vpc_id', 'N/A')} | {igw['state']} | {igw['region']} |\n")
            else:
                f.write("No Internet Gateways found.\n")
            f.write("\n")
            
            f.write("## NAT Gateways\n\n")
            if network_data['nat_gateways']:
                f.write("| NAT Gateway ID | Subnet | VPC | State | Public IP | Region |\n")
                f.write("|---------------|--------|-----|-------|-----------|--------|\n")
                for nat in network_data['nat_gateways']:
                    f.write(f"| {nat['nat_gateway_id']} | {nat['subnet_id']} | {nat['vpc_id']} | {nat['state']} | {nat.get('public_ip', 'N/A')} | {nat['region']} |\n")
            else:
                f.write("No NAT Gateways found.\n")
            f.write("\n")
            
            f.write("## Route Tables\n\n")
            if network_data['route_tables']:
                f.write("| Route Table ID | VPC | Main | Routes | Associated Subnets | Region |\n")
                f.write("|---------------|-----|------|--------|-------------------|--------|\n")
                for rt in network_data['route_tables']:
                    route_count = len(rt.get('routes', []))
                    subnet_count = len(rt.get('associations', []))
                    f.write(f"| {rt['route_table_id']} | {rt['vpc_id']} | {rt['is_main']} | {route_count} | {subnet_count} | {rt['region']} |\n")
            else:
                f.write("No Route Tables found.\n")
            f.write("\n")
        
        return file_path
    
    def _generate_csv_report(self, network_data: Dict[str, Any], output_dir: str) -> str:
        """Generate CSV network report."""
        file_path = os.path.join(output_dir, f"network_infrastructure_{self.timestamp}.csv")
        
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "resource_type", "resource_id", "name", "vpc_id", "subnet_id",
                "cidr_block", "protocol", "port_range", "source_destination",
                "state", "region", "tags", "additional_info"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write VPCs
            for vpc in network_data['vpcs']:
                writer.writerow({
                    "resource_type": "VPC",
                    "resource_id": vpc['vpc_id'],
                    "name": vpc.get('tags', {}).get('Name', ''),
                    "vpc_id": vpc['vpc_id'],
                    "cidr_block": vpc['cidr_block'],
                    "state": vpc['state'],
                    "region": vpc['region'],
                    "tags": json.dumps(vpc.get('tags', {})),
                    "additional_info": json.dumps({"is_default": vpc['is_default']})
                })
            
            # Write Subnets
            for subnet in network_data['subnets']:
                writer.writerow({
                    "resource_type": "Subnet",
                    "resource_id": subnet['subnet_id'],
                    "name": subnet.get('tags', {}).get('Name', ''),
                    "vpc_id": subnet['vpc_id'],
                    "subnet_id": subnet['subnet_id'],
                    "cidr_block": subnet['cidr_block'],
                    "state": subnet['state'],
                    "region": subnet['region'],
                    "tags": json.dumps(subnet.get('tags', {}))
                })
            
            # Write Security Groups with rules
            for sg in network_data['security_groups']:
                # Ingress rules
                for rule in sg['ingress_rules']:
                    writer.writerow({
                        "resource_type": "Security Group - Ingress",
                        "resource_id": sg['group_id'],
                        "name": sg['group_name'],
                        "vpc_id": sg.get('vpc_id', ''),
                        "protocol": rule['protocol'],
                        "port_range": rule['port_range'],
                        "source_destination": rule['source'],
                        "region": sg['region'],
                        "tags": json.dumps(sg.get('tags', {}))
                    })
                
                # Egress rules
                for rule in sg['egress_rules']:
                    writer.writerow({
                        "resource_type": "Security Group - Egress",
                        "resource_id": sg['group_id'],
                        "name": sg['group_name'],
                        "vpc_id": sg.get('vpc_id', ''),
                        "protocol": rule['protocol'],
                        "port_range": rule['port_range'],
                        "source_destination": rule['destination'],
                        "region": sg['region'],
                        "tags": json.dumps(sg.get('tags', {}))
                    })
            
            # Write Network ACLs with rules
            for nacl in network_data['network_acls']:
                for rule in nacl['ingress_rules']:
                    writer.writerow({
                        "resource_type": "Network ACL - Ingress",
                        "resource_id": nacl['network_acl_id'],
                        "vpc_id": nacl.get('vpc_id', ''),
                        "protocol": rule['protocol'],
                        "port_range": rule['port_range'],
                        "source_destination": rule['cidr_block'],
                        "region": nacl['region'],
                        "additional_info": json.dumps({"rule_number": rule['rule_number'], "action": rule['rule_action']})
                    })
                
                for rule in nacl['egress_rules']:
                    writer.writerow({
                        "resource_type": "Network ACL - Egress",
                        "resource_id": nacl['network_acl_id'],
                        "vpc_id": nacl.get('vpc_id', ''),
                        "protocol": rule['protocol'],
                        "port_range": rule['port_range'],
                        "source_destination": rule['cidr_block'],
                        "region": nacl['region'],
                        "additional_info": json.dumps({"rule_number": rule['rule_number'], "action": rule['rule_action']})
                    })
            
            # Write VPC Endpoints
            for endpoint in network_data['vpc_endpoints']:
                writer.writerow({
                    "resource_type": "VPC Endpoint",
                    "resource_id": endpoint['vpc_endpoint_id'],
                    "name": endpoint['service_name'],
                    "vpc_id": endpoint['vpc_id'],
                    "state": endpoint['state'],
                    "region": endpoint['region'],
                    "additional_info": json.dumps({"type": endpoint['vpc_endpoint_type']})
                })
            
            # Write Load Balancers
            for lb in network_data['load_balancers']:
                name = lb.get('load_balancer_name') or lb.get('load_balancer_arn', 'N/A')
                writer.writerow({
                    "resource_type": f"Load Balancer ({lb['type']})",
                    "resource_id": lb.get('load_balancer_arn') or lb.get('load_balancer_name', ''),
                    "name": name,
                    "vpc_id": lb.get('vpc_id', ''),
                    "state": lb.get('state', 'N/A'),
                    "region": lb['region'],
                    "additional_info": json.dumps({"scheme": lb.get('scheme', ''), "listener_count": len(lb.get('listeners', []))})
                })
            
            # Write other resources
            for igw in network_data['internet_gateways']:
                writer.writerow({
                    "resource_type": "Internet Gateway",
                    "resource_id": igw['internet_gateway_id'],
                    "vpc_id": igw.get('vpc_id', ''),
                    "state": igw['state'],
                    "region": igw['region']
                })
            
            for nat in network_data['nat_gateways']:
                writer.writerow({
                    "resource_type": "NAT Gateway",
                    "resource_id": nat['nat_gateway_id'],
                    "subnet_id": nat['subnet_id'],
                    "vpc_id": nat['vpc_id'],
                    "state": nat['state'],
                    "region": nat['region'],
                    "additional_info": json.dumps({"public_ip": nat.get('public_ip', '')})
                })
        
        return file_path
    
    def _generate_json_report(self, network_data: Dict[str, Any], output_dir: str) -> str:
        """Generate JSON network report."""
        file_path = os.path.join(output_dir, f"network_infrastructure_{self.timestamp}.json")
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(network_data, f, indent=2, default=str)
        
        return file_path

