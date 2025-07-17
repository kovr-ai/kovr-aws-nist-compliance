#!/usr/bin/env python3
"""Base class for all security checks."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class BaseSecurityCheck(ABC):
    """Abstract base class for all security checks."""

    def __init__(self, aws_connector, regions: Optional[List[str]] = None):
        """Initialize base security check.
        
        Args:
            aws_connector: AWS connector instance
            regions: List of regions to check (None means all regions)
        """
        self.aws = aws_connector
        self.regions = regions or self.aws.get_all_regions()
        self.findings: List[Dict[str, Any]] = []
        self.resources_checked: Set[str] = set()
        self.check_metadata: Dict[str, Any] = {}
        
    @abstractmethod
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the security check.
        
        Returns:
            List of findings (empty list means check passed)
        """
        pass
    
    @property
    @abstractmethod
    def check_id(self) -> str:
        """Return the unique check identifier."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Return the check description."""
        pass
    
    @property
    def frameworks(self) -> Dict[str, List[str]]:
        """Return framework mappings.
        
        Returns:
            Dict mapping framework IDs to control IDs
        """
        return {}
    
    def add_finding(
        self,
        resource_type: str,
        resource_id: str,
        region: str,
        severity: str,
        details: str,
        recommendation: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a finding to the results.
        
        Args:
            resource_type: Type of AWS resource
            resource_id: Resource identifier
            region: AWS region
            severity: Finding severity (LOW, MEDIUM, HIGH, CRITICAL)
            details: Description of the finding
            recommendation: Remediation recommendation
            evidence: Additional evidence data
        """
        finding = {
            "type": resource_type,
            "id": resource_id,
            "region": region,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if recommendation:
            finding["recommendation"] = recommendation
            
        if evidence:
            finding["evidence"] = evidence
            
        self.findings.append(finding)
        self.resources_checked.add(f"{resource_type}:{resource_id}")
    
    def get_check_result(self) -> Dict[str, Any]:
        """Get formatted check result.
        
        Returns:
            Dictionary containing check results and metadata
        """
        return {
            "check_id": self.check_id,
            "check_name": self.description,
            "timestamp": datetime.utcnow().isoformat(),
            "account_id": self.aws.account_id,
            "status": "FAIL" if self.findings else "PASS",
            "findings": self.findings,
            "resources_checked": list(self.resources_checked),
            "frameworks": self.frameworks,
            "metadata": self.check_metadata
        }
    
    def handle_error(self, error: Exception, context: str) -> None:
        """Handle and log errors during check execution.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
        """
        if isinstance(error, ClientError):
            error_code = error.response['Error']['Code']
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Access denied for {context}: {str(error)}")
                self.check_metadata["access_denied"] = True
            else:
                logger.error(f"AWS error in {context}: {str(error)}")
        else:
            logger.error(f"Error in {context}: {str(error)}")
    
    def check_service_availability(self, service: str, region: str) -> bool:
        """Check if a service is available in a region.
        
        Args:
            service: AWS service name
            region: AWS region
            
        Returns:
            True if service is available, False otherwise
        """
        try:
            self.aws.get_client(service, region)
            return True
        except Exception:
            return False