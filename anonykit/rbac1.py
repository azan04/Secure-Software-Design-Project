"""Role-Based Access Control (RBAC) system"""
import json
from typing import Dict, List, Optional, Set
from enum import Enum
from pathlib import Path
import bcrypt

class Role(Enum):
    """User roles with different permission levels"""
    ADMIN = "admin"
    DATA_OWNER = "data_owner"
    DATA_ANALYST = "data_analyst"
    VIEWER = "viewer"

class Permission(Enum):
    """Granular permissions for operations"""
    READ_DATA = "read_data"
    WRITE_DATA = "write_data"
    MASK_DATA = "mask_data"
    ANONYMIZE_DATA = "anonymize_data"
    CONFIGURE_PROFILE = "configure_profile"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_USERS = "manage_users"
    EXPORT_DATA = "export_data"
    DELETE_DATA = "delete_data"
    CONFIGURE_K_ANONYMITY = "configure_k_anonymity"
    CONFIGURE_L_DIVERSITY = "configure_l_diversity"
    CONFIGURE_DIFF_PRIVACY = "configure_diff_privacy"

# Role-permission mappings
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.READ_DATA,
        Permission.WRITE_DATA,
        Permission.MASK_DATA,
        Permission.ANONYMIZE_DATA,
        Permission.CONFIGURE_PROFILE,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_USERS,
        Permission.EXPORT_DATA,
        Permission.DELETE_DATA,
        Permission.CONFIGURE_K_ANONYMITY,
        Permission.CONFIGURE_L_DIVERSITY,
        Permission.CONFIGURE_DIFF_PRIVACY,
    },
    Role.DATA_OWNER: {
        Permission.READ_DATA,
        Permission.WRITE_DATA,
        Permission.MASK_DATA,
        Permission.ANONYMIZE_DATA,
        Permission.CONFIGURE_PROFILE,
        Permission.EXPORT_DATA,
        Permission.CONFIGURE_K_ANONYMITY,
        Permission.CONFIGURE_L_DIVERSITY,
        Permission.CONFIGURE_DIFF_PRIVACY,
    },
    Role.DATA_ANALYST: {
        Permission.READ_DATA,
        Permission.EXPORT_DATA,
    },
    Role.VIEWER: {
        Permission.READ_DATA,
    },
}

class User:
    """User with role and permissions"""
    
    def __init__(self, username: str, role: Role, password_hash: Optional[str] = None):
        self.username = username
        self.role = role
        self.password_hash = password_hash
        self.active = True
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        if not self.active:
            return False
        return permission in ROLE_PERMISSIONS.get(self.role, set())
    
    def set_password(self, password: str):
        """Set user password (bcrypt hash)"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str) -> bool:
        """Verify password against bcrypt hash"""
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def to_dict(self) -> Dict:
        """Serialize user to dictionary"""
        return {
            'username': self.username,
            'role': self.role.value,
            'password_hash': self.password_hash,
            'active': self.active
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Deserialize user from dictionary"""
        user = cls(
            username=data['username'],
            role=Role(data['role']),
            password_hash=data.get('password_hash')
        )
        user.active = data.get('active', True)
        return user

class RBACManager:
    """Manages users, roles, and access control"""
    
    def __init__(self, config_file: str = "rbac_config.json"):
        self.config_file = config_file
        self.users: Dict[str, User] = {}
        self.load_config()
        
        # Initialize default users if none exist
        if not self.users:
            self._initialize_default_users()
        self._ensure_default_admin()
    
    def _ensure_default_admin(self):
        """Ensure at least one admin user exists"""
        if not any(u.role == Role.ADMIN for u in self.users.values()):
            admin = User("admin", Role.ADMIN)
            admin.set_password("admin123")  # Default password - should be changed!
            self.users["admin"] = admin
            self.save_config()
    
    def _initialize_default_users(self):
        """Initialize default users for the system"""
        default_users = [
            ('admin', Role.ADMIN, 'admin123'),
            ('data_owner', Role.DATA_OWNER, 'owner123'),
            ('data_analyst', Role.DATA_ANALYST, 'analyst123'),
            ('viewer', Role.VIEWER, 'viewer123')
        ]
        
        for username, role, password in default_users:
            user = User(username, role)
            user.set_password(password)
            self.users[username] = user
        
        self.save_config()
        print(f"Initialized {len(default_users)} default users")
    
    def load_config(self):
        """Load RBAC configuration from file"""
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.users = {
                        username: User.from_dict(user_data)
                        for username, user_data in data.get('users', {}).items()
                    }
            except Exception as e:
                print(f"Error loading RBAC config: {e}")
                self.users = {}
    
    def save_config(self):
        """Save RBAC configuration to file"""
        data = {
            'users': {
                username: user.to_dict()
                for username, user in self.users.items()
            }
        }
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_user(self, username: str, role: Role, password: str) -> User:
        """Add new user"""
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        
        user = User(username, role)
        user.set_password(password)
        self.users[username] = user
        self.save_config()
        return user
    
    def remove_user(self, username: str):
        """Remove user"""
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        
        # Prevent removing last admin
        if self.users[username].role == Role.ADMIN:
            admin_count = sum(1 for u in self.users.values() if u.role == Role.ADMIN)
            if admin_count <= 1:
                raise ValueError("Cannot remove last admin user")
        
        del self.users[username]
        self.save_config()
    
    def update_user_role(self, username: str, new_role: Role):
        """Update user's role"""
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        
        # Prevent demoting last admin
        if self.users[username].role == Role.ADMIN and new_role != Role.ADMIN:
            admin_count = sum(1 for u in self.users.values() if u.role == Role.ADMIN)
            if admin_count <= 1:
                raise ValueError("Cannot demote last admin user")
        
        self.users[username].role = new_role
        self.save_config()
    
    def deactivate_user(self, username: str):
        """Deactivate user account"""
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        self.users[username].active = False
        self.save_config()
    
    def activate_user(self, username: str):
        """Activate user account"""
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        self.users[username].active = True
        self.save_config()
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.users.get(username)
        if user and user.active and user.verify_password(password):
            return user
        return None
    
    def check_permission(self, username: str, permission: Permission) -> bool:
        """Check if user has permission"""
        user = self.users.get(username)
        if not user:
            return False
        return user.has_permission(permission)
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.users.get(username)
    
    def list_users(self) -> List[User]:
        """List all users"""
        return list(self.users.values())
    
    def get_users_by_role(self, role: Role) -> List[User]:
        """Get all users with specific role"""
        return [u for u in self.users.values() if u.role == role]

class AccessControlDecorator:
    """Decorator for enforcing access control on functions"""
    
    def __init__(self, rbac_manager: RBACManager):
        self.rbac_manager = rbac_manager
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Get username from kwargs or current context
                username = kwargs.get('user') or kwargs.get('username')
                if not username:
                    raise PermissionError("User authentication required")
                
                if not self.rbac_manager.check_permission(username, permission):
                    user = self.rbac_manager.get_user(username)
                    role = user.role.value if user else "unknown"
                    raise PermissionError(
                        f"User '{username}' with role '{role}' lacks permission: {permission.value}"
                    )
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_role(self, required_role: Role):
        """Decorator to require specific role"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                username = kwargs.get('user') or kwargs.get('username')
                if not username:
                    raise PermissionError("User authentication required")
                
                user = self.rbac_manager.get_user(username)
                if not user or user.role != required_role:
                    raise PermissionError(
                        f"User '{username}' does not have required role: {required_role.value}"
                    )
                
                return func(*args, **kwargs)
            return wrapper
        return decorator

# Global RBAC manager instance
_global_rbac: Optional[RBACManager] = None

def get_rbac_manager(config_file: str = "rbac_config.json") -> RBACManager:
    """Get or create global RBAC manager"""
    global _global_rbac
    if _global_rbac is None:
        _global_rbac = RBACManager(config_file)
    return _global_rbac
