"""
Unit tests for RBAC system
"""
import pytest
import os
import json
from anonykit.rbac import User, Role, Permission, RBACManager


class TestUser:
    """Test User class"""
    
    def test_user_creation(self):
        user = User("testuser", Role.DATA_ANALYST)
        user.set_password("password123")
        assert user.username == "testuser"
        assert user.role == Role.DATA_ANALYST
        assert user.password_hash != "password123"  # Should be hashed
    
    def test_password_verification(self):
        user = User("testuser", Role.DATA_ANALYST)
        user.set_password("password123")
        assert user.verify_password("password123") is True
        assert user.verify_password("wrongpassword") is False
    
    def test_has_permission(self):
        admin = User("admin", Role.ADMIN)
        analyst = User("analyst", Role.DATA_ANALYST)
        viewer = User("viewer", Role.VIEWER)
        
        assert admin.has_permission(Permission.MANAGE_USERS) is True
        assert analyst.has_permission(Permission.READ_DATA) is True
        assert viewer.has_permission(Permission.MANAGE_USERS) is False


class TestRBACManager:
    """Test RBAC Manager"""
    
    @pytest.fixture
    def rbac_manager(self, tmp_path):
        # Use temporary file for testing
        test_file = tmp_path / "test_users.json"
        manager = RBACManager(str(test_file))
        return manager
    
    def test_create_user(self, rbac_manager):
        user = rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password")
        assert user is not None
        assert user.username == "testuser"
    
    def test_create_duplicate_user(self, rbac_manager):
        rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password")
        try:
            rbac_manager.add_user("testuser", Role.ADMIN, "password2")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
    
    def test_authenticate(self, rbac_manager):
        rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password123")
        
        user = rbac_manager.users.get("testuser")
        assert user is not None
        assert user.verify_password("password123") is True
        assert user.verify_password("wrongpassword") is False
    
    def test_get_user(self, rbac_manager):
        rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password")
        
        user = rbac_manager.users.get("testuser")
        assert user is not None
        assert user.username == "testuser"
        
        nonexistent = rbac_manager.users.get("nonexistent")
        assert nonexistent is None
    
    def test_update_user_role(self, rbac_manager):
        rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password")
        
        rbac_manager.update_user_role("testuser", Role.ADMIN)
        
        user = rbac_manager.users.get("testuser")
        assert user.role == Role.ADMIN
    
    def test_delete_user(self, rbac_manager):
        rbac_manager.add_user("testuser", Role.DATA_ANALYST, "password")
        
        rbac_manager.remove_user("testuser")
        
        user = rbac_manager.users.get("testuser")
        assert user is None
    
    def test_list_users(self, rbac_manager):
        rbac_manager.add_user("user1", Role.DATA_ANALYST, "pass")
        rbac_manager.add_user("user2", Role.VIEWER, "pass")
        
        users = list(rbac_manager.users.keys())
        assert len(users) >= 2
        assert "user1" in users
        assert "user2" in users
    
    def test_persistence(self, tmp_path):
        # Create manager and add user
        test_file = tmp_path / "test_users.json"
        manager1 = RBACManager(str(test_file))
        manager1.add_user("testuser", Role.DATA_ANALYST, "password")
        
        # Create new manager instance (simulates restart)
        manager2 = RBACManager(str(test_file))
        user = manager2.users.get("testuser")
        assert user is not None
        assert user.username == "testuser"
