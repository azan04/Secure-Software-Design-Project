"""Audit logging system for compliance and security tracking"""
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
import os

class AuditLogger:
    """Comprehensive audit logging for all anonymization operations"""
    
    def __init__(self, log_file: str = "anonykit_audit.log", log_level: int = logging.INFO):
        """
        Initialize audit logger
        
        Args:
            log_file: Path to audit log file
            log_level: Logging level
        """
        self.log_file = log_file
        self.logger = logging.getLogger('anonykit_audit')
        self.logger.setLevel(log_level)
        
        # Create logs directory if it doesn't exist
        log_dir = Path(log_file).parent
        if log_dir and not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler for audit logs
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(log_level)
        
        # JSON formatter for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
        
        # Also log to console for debugging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        self.logger.addHandler(console_handler)
    
    def _format_message(self, event_type: str, details: Dict[str, Any], 
                       user: Optional[str] = None, success: bool = True) -> str:
        """Format audit log message as JSON"""
        log_entry = {
            'event_type': event_type,
            'user': user or os.getenv('USERNAME', 'unknown'),
            'success': success,
            'details': details
        }
        return json.dumps(log_entry)
    
    def log_data_access(self, file_path: str, operation: str, user: Optional[str] = None,
                       records_count: Optional[int] = None):
        """Log data access operations"""
        details = {
            'operation': operation,
            'file_path': file_path,
            'records_count': records_count
        }
        message = self._format_message('DATA_ACCESS', details, user)
        self.logger.info(message)
    
    def log_transformation(self, transformation_type: str, column: str, 
                          parameters: Dict[str, Any], records_affected: int,
                          user: Optional[str] = None):
        """Log transformation operations"""
        details = {
            'transformation_type': transformation_type,
            'column': column,
            'parameters': parameters,
            'records_affected': records_affected
        }
        message = self._format_message('TRANSFORMATION', details, user)
        self.logger.info(message)
    
    def log_anonymization(self, method: str, input_file: str, output_file: str,
                         original_records: int, anonymized_records: int,
                         suppression_rate: float, parameters: Dict[str, Any],
                         user: Optional[str] = None):
        """Log anonymization operations"""
        details = {
            'method': method,
            'input_file': input_file,
            'output_file': output_file,
            'original_records': original_records,
            'anonymized_records': anonymized_records,
            'suppression_rate': suppression_rate,
            'parameters': parameters
        }
        message = self._format_message('ANONYMIZATION', details, user)
        self.logger.info(message)
    
    def log_k_anonymity(self, k: int, quasi_identifiers: List[str], 
                       satisfies: bool, min_group_size: int,
                       input_file: str, user: Optional[str] = None):
        """Log k-anonymity operations"""
        details = {
            'k': k,
            'quasi_identifiers': quasi_identifiers,
            'satisfies': satisfies,
            'min_group_size': min_group_size,
            'input_file': input_file
        }
        message = self._format_message('K_ANONYMITY', details, user, success=satisfies)
        self.logger.info(message)
    
    def log_l_diversity(self, l: int, sensitive_attribute: str,
                       satisfies: bool, min_diversity: int,
                       input_file: str, user: Optional[str] = None):
        """Log l-diversity operations"""
        details = {
            'l': l,
            'sensitive_attribute': sensitive_attribute,
            'satisfies': satisfies,
            'min_diversity': min_diversity,
            'input_file': input_file
        }
        message = self._format_message('L_DIVERSITY', details, user, success=satisfies)
        self.logger.info(message)
    
    def log_differential_privacy(self, epsilon: float, delta: float,
                                columns: List[str], budget_used: float,
                                input_file: str, user: Optional[str] = None):
        """Log differential privacy operations"""
        details = {
            'epsilon': epsilon,
            'delta': delta,
            'columns': columns,
            'budget_used': budget_used,
            'input_file': input_file
        }
        message = self._format_message('DIFFERENTIAL_PRIVACY', details, user)
        self.logger.info(message)
    
    def log_access_control(self, user: str, role: str, resource: str,
                          action: str, granted: bool, reason: Optional[str] = None):
        """Log access control decisions"""
        details = {
            'role': role,
            'resource': resource,
            'action': action,
            'granted': granted,
            'reason': reason
        }
        message = self._format_message('ACCESS_CONTROL', details, user, success=granted)
        self.logger.warning(message) if not granted else self.logger.info(message)
    
    def log_security_event(self, event_type: str, description: str,
                          severity: str = 'INFO', user: Optional[str] = None,
                          additional_data: Optional[Dict[str, Any]] = None):
        """Log security-related events"""
        details = {
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'additional_data': additional_data or {}
        }
        message = self._format_message('SECURITY_EVENT', details, user)
        
        if severity == 'CRITICAL':
            self.logger.critical(message)
        elif severity == 'ERROR':
            self.logger.error(message)
        elif severity == 'WARNING':
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def log_error(self, error_type: str, error_message: str, 
                 file_path: Optional[str] = None, user: Optional[str] = None,
                 stack_trace: Optional[str] = None):
        """Log errors and exceptions"""
        details = {
            'error_type': error_type,
            'error_message': error_message,
            'file_path': file_path,
            'stack_trace': stack_trace
        }
        message = self._format_message('ERROR', details, user, success=False)
        self.logger.error(message)
    
    def log_profile_load(self, profile_path: str, columns_configured: int,
                        user: Optional[str] = None):
        """Log profile configuration loading"""
        details = {
            'profile_path': profile_path,
            'columns_configured': columns_configured
        }
        message = self._format_message('PROFILE_LOAD', details, user)
        self.logger.info(message)
    
    def log_data_export(self, output_file: str, records_count: int,
                       format_type: str, user: Optional[str] = None):
        """Log data export operations"""
        details = {
            'output_file': output_file,
            'records_count': records_count,
            'format': format_type
        }
        message = self._format_message('DATA_EXPORT', details, user)
        self.logger.info(message)
    
    def log_validation(self, validation_type: str, passed: bool,
                      details: Dict[str, Any], user: Optional[str] = None):
        """Log validation checks"""
        log_details = {
            'validation_type': validation_type,
            'passed': passed,
            'details': details
        }
        message = self._format_message('VALIDATION', log_details, user, success=passed)
        if not passed:
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def get_audit_trail(self, lines: int = 100) -> List[str]:
        """Retrieve recent audit log entries"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return f.readlines()[-lines:]
        except FileNotFoundError:
            return []
    
    def search_logs(self, event_type: Optional[str] = None,
                   user: Optional[str] = None,
                   start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Search audit logs with filters"""
        results = []
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        # Apply filters
                        if event_type and entry.get('message', {}).get('event_type') != event_type:
                            continue
                        if user and entry.get('message', {}).get('user') != user:
                            continue
                        
                        # Date filtering
                        timestamp_str = entry.get('timestamp', '')
                        if timestamp_str:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            if start_date and timestamp < start_date:
                                continue
                            if end_date and timestamp > end_date:
                                continue
                        
                        results.append(entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        return results


# Global audit logger instance
_global_logger: Optional[AuditLogger] = None

def get_audit_logger(log_file: str = "anonykit_audit.log") -> AuditLogger:
    """Get or create global audit logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = AuditLogger(log_file)
    return _global_logger
