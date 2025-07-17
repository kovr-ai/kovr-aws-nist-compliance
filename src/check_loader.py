#!/usr/bin/env python3
"""Dynamic loader for modular security checks."""

import importlib
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Type

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_checks.base import BaseSecurityCheck

logger = logging.getLogger(__name__)


class CheckLoader:
    """Loads and manages security check modules."""
    
    def __init__(self, config_path: str = None):
        """Initialize check loader.
        
        Args:
            config_path: Path to enhanced checks configuration
        """
        if config_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, "security_checks", "complete_enhanced_checks_config.json")
            
        self.config_path = config_path
        self.checks_config = self._load_config()
        self.loaded_modules = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load enhanced checks configuration."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded {config['metadata']['total_checks']} checks from configuration")
            return config
        except Exception as e:
            logger.error(f"Failed to load checks configuration: {e}")
            raise
            
    def get_check_class(self, check_id: str) -> Optional[Type[BaseSecurityCheck]]:
        """Get check class for a given check ID.
        
        Args:
            check_id: Check identifier
            
        Returns:
            Check class or None if not found
        """
        # Find check configuration
        check_config = None
        for check in self.checks_config['security_checks']:
            if check['id'] == check_id:
                check_config = check
                break
                
        if not check_config:
            logger.warning(f"Check {check_id} not found in configuration")
            return None
            
        # Get module path
        module_path = check_config['execution']['module']
        
        # Check if already loaded
        if module_path in self.loaded_modules:
            return self.loaded_modules[module_path]
            
        try:
            # Import module
            module = importlib.import_module(module_path)
            
            # Find check class (should be the only class inheriting from BaseSecurityCheck)
            check_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BaseSecurityCheck) and 
                    attr != BaseSecurityCheck):
                    check_class = attr
                    break
                    
            if check_class:
                self.loaded_modules[module_path] = check_class
                logger.debug(f"Loaded check class for {check_id} from {module_path}")
                return check_class
            else:
                logger.error(f"No check class found in module {module_path}")
                return None
                
        except ImportError as e:
            logger.warning(f"Failed to import module {module_path}: {e}")
            # Return None for placeholder modules
            return None
        except Exception as e:
            logger.error(f"Error loading check {check_id}: {e}")
            return None
            
    def get_all_checks(self) -> List[Dict[str, Any]]:
        """Get all check configurations."""
        return self.checks_config['security_checks']
        
    def get_checks_by_service(self, service: str) -> List[Dict[str, Any]]:
        """Get checks for a specific service."""
        return [
            check for check in self.checks_config['security_checks']
            if check['service'] == service
        ]
        
    def get_checks_by_severity(self, min_severity: str) -> List[Dict[str, Any]]:
        """Get checks meeting minimum severity threshold."""
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(min_severity)
        
        return [
            check for check in self.checks_config['security_checks']
            if severity_order.index(check['severity']) >= min_index
        ]
        
    def instantiate_check(
        self, 
        check_id: str, 
        aws_connector, 
        regions: Optional[List[str]] = None
    ) -> Optional[BaseSecurityCheck]:
        """Create an instance of a check.
        
        Args:
            check_id: Check identifier
            aws_connector: AWS connector instance
            regions: List of regions to check
            
        Returns:
            Check instance or None if check cannot be loaded
        """
        check_class = self.get_check_class(check_id)
        if check_class:
            return check_class(aws_connector, regions)
        return None