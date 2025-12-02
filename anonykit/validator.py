"""Input validation and security utilities"""
import os
import re
from pathlib import Path
from typing import Optional, List, Any, Dict
import json
import html

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class Validator:
    """Comprehensive input validation for security"""
    
    # Dangerous patterns that could indicate injection attacks
    DANGEROUS_PATTERNS = [
        r'[;&|`$]',  # Shell metacharacters
        r'\.\.',     # Directory traversal
        r'<script',  # XSS attempts
        r'javascript:',  # JavaScript injection
        r'eval\(',   # Code execution
        r'exec\(',   # Code execution
        r'import\s+os',  # Dangerous imports
        r'__import__',   # Dynamic imports
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"('\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*)",  # ' OR '1'='1
        r'(--|\#|\/\*|\*\/)',  # SQL comments
        r'(\bUNION\b.*\bSELECT\b)',  # UNION SELECT
        r'(\bDROP\b.*\bTABLE\b)',  # DROP TABLE
        r'(\bINSERT\b.*\bINTO\b)',  # INSERT INTO
        r'(\bUPDATE\b.*\bSET\b)',  # UPDATE SET
        r'(\bDELETE\b.*\bFROM\b)',  # DELETE FROM
        r'(\bEXEC\b|\bEXECUTE\b)',  # EXEC/EXECUTE
        r'(\bCAST\b|\bCONVERT\b)',  # Type casting
        r'(\bCONCAT\b)',  # String concatenation
        r'(xp_|sp_)',  # SQL Server stored procedures
        r'(;.*\b(DROP|CREATE|ALTER|TRUNCATE)\b)',  # Chained commands
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'on\w+\s*=',  # Event handlers (onclick, onerror, etc.)
        r'javascript:',  # JavaScript protocol
        r'<iframe',  # Iframes
        r'<object',  # Objects
        r'<embed',  # Embeds
        r'<img[^>]+src[^>]*>',  # Image tags with suspicious content
    ]
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'.csv', '.json', '.txt', '.tsv'}
    
    @staticmethod
    def sanitize_sql_input(input_str: str) -> str:
        """
        Sanitize input to prevent SQL injection
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string safe for SQL operations
        """
        if not isinstance(input_str, str):
            return str(input_str)
        
        # Remove null bytes
        input_str = input_str.replace('\x00', '')
        
        # Escape single quotes (most common SQL injection vector)
        input_str = input_str.replace("'", "''")
        
        # Remove or escape dangerous SQL characters
        input_str = input_str.replace(';', '')  # Prevent statement chaining
        input_str = input_str.replace('--', '')  # Remove SQL comments
        input_str = input_str.replace('/*', '')  # Remove block comments
        input_str = input_str.replace('*/', '')
        input_str = input_str.replace('xp_', '')  # Remove SQL Server extended procs
        
        return input_str.strip()
    
    @staticmethod
    def is_sql_injection_attempt(input_str: str) -> bool:
        """
        Detect potential SQL injection attempts
        
        Args:
            input_str: Input string to check
            
        Returns:
            True if potential SQL injection detected
        """
        if not isinstance(input_str, str):
            return False
        
        # Convert to uppercase for case-insensitive matching
        input_upper = input_str.upper()
        
        # Check for SQL injection patterns
        for pattern in Validator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def sanitize_xss_input(input_str: str) -> str:
        """
        Sanitize input to prevent XSS attacks
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string safe for HTML output
        """
        if not isinstance(input_str, str):
            return str(input_str)
        
        # HTML escape special characters
        input_str = html.escape(input_str)
        
        # Additional XSS-specific sanitization
        input_str = re.sub(r'<script[^>]*>.*?</script>', '', input_str, flags=re.IGNORECASE | re.DOTALL)
        input_str = re.sub(r'javascript:', '', input_str, flags=re.IGNORECASE)
        input_str = re.sub(r'on\w+\s*=', '', input_str, flags=re.IGNORECASE)
        
        return input_str
    
    @staticmethod
    def is_xss_attempt(input_str: str) -> bool:
        """
        Detect potential XSS attempts
        
        Args:
            input_str: Input string to check
            
        Returns:
            True if potential XSS detected
        """
        if not isinstance(input_str, str):
            return False
        
        for pattern in Validator.XSS_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def validate_username(username: str) -> str:
        """
        Validate and sanitize username input
        
        Args:
            username: Username to validate
            
        Returns:
            Validated username
            
        Raises:
            ValidationError: If validation fails
        """
        if not username or not isinstance(username, str):
            raise ValidationError("Username must be a non-empty string")
        
        username = username.strip()
        
        # Check length
        if len(username) < 3 or len(username) > 50:
            raise ValidationError("Username must be between 3 and 50 characters")
        
        # Check for SQL injection
        if Validator.is_sql_injection_attempt(username):
            raise ValidationError("Username contains invalid characters")
        
        # Only allow alphanumeric, underscore, hyphen, and dot
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            raise ValidationError("Username can only contain letters, numbers, dots, hyphens, and underscores")
        
        return username
    
    @staticmethod
    def validate_string_input(input_str: str, field_name: str = "Input", 
                            max_length: int = 1000, allow_special: bool = False) -> str:
        """
        Validate general string input with injection prevention
        
        Args:
            input_str: String to validate
            field_name: Name of field for error messages
            max_length: Maximum allowed length
            allow_special: Whether to allow special characters
            
        Returns:
            Validated string
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(input_str, str):
            raise ValidationError(f"{field_name} must be a string")
        
        input_str = input_str.strip()
        
        # Check length
        if len(input_str) > max_length:
            raise ValidationError(f"{field_name} exceeds maximum length of {max_length}")
        
        # Check for SQL injection
        if Validator.is_sql_injection_attempt(input_str):
            raise ValidationError(f"{field_name} contains potentially malicious content")
        
        # Check for XSS
        if Validator.is_xss_attempt(input_str):
            raise ValidationError(f"{field_name} contains potentially malicious content")
        
        # Check for command injection patterns
        for pattern in Validator.DANGEROUS_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                raise ValidationError(f"{field_name} contains invalid characters")
        
        return input_str
    
    @staticmethod
    def validate_json_input(json_str: str, max_size: int = 1024 * 1024) -> Dict:
        """
        Validate JSON input with size limits
        
        Args:
            json_str: JSON string to validate
            max_size: Maximum size in bytes
            
        Returns:
            Parsed JSON object
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(json_str, str):
            raise ValidationError("JSON input must be a string")
        
        # Check size
        if len(json_str.encode('utf-8')) > max_size:
            raise ValidationError(f"JSON input exceeds maximum size of {max_size} bytes")
        
        # Parse JSON
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {str(e)}")
        
        # Validate nested strings in JSON
        Validator._validate_json_strings(data)
        
        return data
    
    @staticmethod
    def _validate_json_strings(obj: Any, depth: int = 0, max_depth: int = 10):
        """
        Recursively validate strings in JSON structure
        
        Args:
            obj: JSON object to validate
            depth: Current recursion depth
            max_depth: Maximum allowed depth
            
        Raises:
            ValidationError: If validation fails
        """
        if depth > max_depth:
            raise ValidationError("JSON structure too deeply nested")
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Validate keys
                if isinstance(key, str):
                    if Validator.is_sql_injection_attempt(key) or Validator.is_xss_attempt(key):
                        raise ValidationError(f"JSON key contains potentially malicious content: {key}")
                Validator._validate_json_strings(value, depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                Validator._validate_json_strings(item, depth + 1, max_depth)
        elif isinstance(obj, str):
            if Validator.is_sql_injection_attempt(obj) or Validator.is_xss_attempt(obj):
                raise ValidationError("JSON value contains potentially malicious content")
    
    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = False, 
                          allow_create: bool = False) -> str:
        """
        Validate and sanitize file paths
        
        Args:
            file_path: Path to validate
            must_exist: Whether file must already exist
            allow_create: Whether creating new file is allowed
            
        Returns:
            Validated absolute path
            
        Raises:
            ValidationError: If validation fails
        """
        if not file_path or not isinstance(file_path, str):
            raise ValidationError("File path must be a non-empty string")
        
        # Remove any null bytes
        file_path = file_path.replace('\x00', '')
        
        # Check for dangerous patterns
        for pattern in Validator.DANGEROUS_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                raise ValidationError(f"File path contains dangerous pattern: {pattern}")
        
        # Convert to Path object for safe manipulation
        try:
            path = Path(file_path).resolve()
        except Exception as e:
            raise ValidationError(f"Invalid file path: {e}")
        
        # Check for directory traversal attempts
        if '..' in path.parts:
            raise ValidationError("Directory traversal not allowed")
        
        # Validate file extension
        if path.suffix.lower() not in Validator.ALLOWED_EXTENSIONS:
            raise ValidationError(
                f"File extension '{path.suffix}' not allowed. "
                f"Allowed: {', '.join(Validator.ALLOWED_EXTENSIONS)}"
            )
        
        # Check existence requirements
        if must_exist and not path.exists():
            raise ValidationError(f"File does not exist: {path}")
        
        if not allow_create and not must_exist and path.exists():
            raise ValidationError(f"File already exists: {path}")
        
        # Ensure path is not pointing to sensitive system directories
        sensitive_dirs = ['/etc', '/sys', '/proc', 'C:\\Windows\\System32']
        for sensitive in sensitive_dirs:
            try:
                if Path(sensitive) in path.parents:
                    raise ValidationError("Access to system directories not allowed")
            except:
                pass
        
        return str(path)
    
    @staticmethod
    def validate_column_name(column_name: str) -> str:
        """
        Validate column names to prevent injection
        
        Args:
            column_name: Column name to validate
            
        Returns:
            Validated column name
            
        Raises:
            ValidationError: If validation fails
        """
        if not column_name or not isinstance(column_name, str):
            raise ValidationError("Column name must be a non-empty string")
        
        # Remove null bytes and trim whitespace
        column_name = column_name.replace('\x00', '').strip()
        
        # Check length
        if len(column_name) > 255:
            raise ValidationError("Column name too long (max 255 characters)")
        
        # Check for dangerous patterns
        for pattern in Validator.DANGEROUS_PATTERNS:
            if re.search(pattern, column_name, re.IGNORECASE):
                raise ValidationError(f"Column name contains dangerous pattern")
        
        # Only allow alphanumeric, underscore, hyphen
        if not re.match(r'^[a-zA-Z0-9_-]+$', column_name):
            raise ValidationError(
                "Column name can only contain letters, numbers, underscore, and hyphen"
            )
        
        return column_name
    
    @staticmethod
    def validate_profile_json(profile_path: str) -> Dict[str, Any]:
        """
        Validate and load profile JSON safely
        
        Args:
            profile_path: Path to profile JSON
            
        Returns:
            Validated profile dictionary
            
        Raises:
            ValidationError: If validation fails
        """
        # Validate path first
        safe_path = Validator.validate_file_path(profile_path, must_exist=True)
        
        # Check file size (prevent DoS)
        max_size = 10 * 1024 * 1024  # 10MB
        if os.path.getsize(safe_path) > max_size:
            raise ValidationError(f"Profile file too large (max {max_size} bytes)")
        
        # Load and parse JSON
        try:
            with open(safe_path, 'r', encoding='utf-8') as f:
                profile = json.load(f)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON in profile: {e}")
        except Exception as e:
            raise ValidationError(f"Error loading profile: {e}")
        
        # Validate structure
        if not isinstance(profile, dict):
            raise ValidationError("Profile must be a JSON object")
        
        # Validate columns configuration
        if 'columns' in profile:
            if not isinstance(profile['columns'], dict):
                raise ValidationError("'columns' must be an object")
            
            for col_name, col_spec in profile['columns'].items():
                # Validate column name
                Validator.validate_column_name(col_name)
                
                # Validate column specification
                if not isinstance(col_spec, dict):
                    raise ValidationError(f"Column spec for '{col_name}' must be an object")
                
                if 'transform' not in col_spec:
                    raise ValidationError(f"Column '{col_name}' missing 'transform' field")
                
                # Validate transform type
                valid_transforms = {
                    'mask', 'hash', 'hmac', 'generalize_age', 'generalize_numeric',
                    'substitute', 'shuffle', 'null', 'differential_privacy'
                }
                if col_spec['transform'] not in valid_transforms:
                    raise ValidationError(
                        f"Invalid transform '{col_spec['transform']}' for column '{col_name}'"
                    )
        
        return profile
    
    @staticmethod
    def validate_integer(value: Any, min_val: Optional[int] = None, 
                        max_val: Optional[int] = None, name: str = "value") -> int:
        """
        Validate integer input
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            name: Name of parameter for error messages
            
        Returns:
            Validated integer
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            int_val = int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{name} must be an integer")
        
        if min_val is not None and int_val < min_val:
            raise ValidationError(f"{name} must be at least {min_val}")
        
        if max_val is not None and int_val > max_val:
            raise ValidationError(f"{name} must be at most {max_val}")
        
        return int_val
    
    @staticmethod
    def validate_float(value: Any, min_val: Optional[float] = None,
                      max_val: Optional[float] = None, name: str = "value") -> float:
        """
        Validate float input
        
        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            name: Name of parameter for error messages
            
        Returns:
            Validated float
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            float_val = float(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{name} must be a number")
        
        if min_val is not None and float_val < min_val:
            raise ValidationError(f"{name} must be at least {min_val}")
        
        if max_val is not None and float_val > max_val:
            raise ValidationError(f"{name} must be at most {max_val}")
        
        return float_val
    
    @staticmethod
    def validate_string(value: Any, min_length: int = 0, max_length: int = 10000,
                       allowed_chars: Optional[str] = None, name: str = "value") -> str:
        """
        Validate string input
        
        Args:
            value: Value to validate
            min_length: Minimum string length
            max_length: Maximum string length
            allowed_chars: Regex pattern of allowed characters
            name: Name of parameter for error messages
            
        Returns:
            Validated string
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        if len(value) < min_length:
            raise ValidationError(f"{name} must be at least {min_length} characters")
        
        if len(value) > max_length:
            raise ValidationError(f"{name} must be at most {max_length} characters")
        
        if allowed_chars and not re.match(allowed_chars, value):
            raise ValidationError(f"{name} contains invalid characters")
        
        return value
    
    @staticmethod
    def validate_list(value: Any, item_type: type, min_items: int = 0,
                     max_items: int = 1000, name: str = "value") -> List[Any]:
        """
        Validate list input
        
        Args:
            value: Value to validate
            item_type: Expected type of list items
            min_items: Minimum number of items
            max_items: Maximum number of items
            name: Name of parameter for error messages
            
        Returns:
            Validated list
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(value, list):
            raise ValidationError(f"{name} must be a list")
        
        if len(value) < min_items:
            raise ValidationError(f"{name} must contain at least {min_items} items")
        
        if len(value) > max_items:
            raise ValidationError(f"{name} must contain at most {max_items} items")
        
        for i, item in enumerate(value):
            if not isinstance(item, item_type):
                raise ValidationError(
                    f"{name}[{i}] must be of type {item_type.__name__}"
                )
        
        return value
    
    @staticmethod
    def sanitize_output_path(output_path: str, base_dir: Optional[str] = None) -> str:
        """
        Ensure output path is safe and within allowed directory
        
        Args:
            output_path: Desired output path
            base_dir: Base directory to restrict outputs to
            
        Returns:
            Sanitized output path
            
        Raises:
            ValidationError: If path is unsafe
        """
        safe_path = Validator.validate_file_path(output_path, allow_create=True)
        
        if base_dir:
            base = Path(base_dir).resolve()
            output = Path(safe_path).resolve()
            
            # Check if output is within base directory
            try:
                output.relative_to(base)
            except ValueError:
                raise ValidationError(
                    f"Output path must be within {base_dir}"
                )
        
        return safe_path


class SecureConfigLoader:
    """Load configuration files securely"""
    
    @staticmethod
    def load_json_config(config_path: str, schema: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Securely load and validate JSON configuration
        
        Args:
            config_path: Path to config file
            schema: Optional schema to validate against
            
        Returns:
            Validated configuration dictionary
        """
        # Validate path
        safe_path = Validator.validate_file_path(config_path, must_exist=True)
        
        # Load JSON
        config = Validator.validate_profile_json(safe_path)
        
        # Additional schema validation if provided
        if schema:
            SecureConfigLoader._validate_schema(config, schema)
        
        return config
    
    @staticmethod
    def _validate_schema(data: Dict, schema: Dict):
        """Simple schema validation"""
        for key, expected_type in schema.items():
            if key in data:
                if not isinstance(data[key], expected_type):
                    raise ValidationError(
                        f"Config key '{key}' must be of type {expected_type.__name__}"
                    )
