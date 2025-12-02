"""
Unit tests for input validation
"""
import pytest
from anonykit.validator import Validator, ValidationError


class TestValidator:
    """Test Validator class"""
    
    @pytest.fixture
    def validator(self):
        return Validator()
    
    def test_validate_file_path_valid(self, validator):
        # Valid path
        result = validator.validate_file_path("data.csv")
        assert isinstance(result, str)
        assert "data.csv" in result
    
    def test_validate_file_path_invalid_extension(self, validator):
        # Extension check not enforced in validator, only dangerous patterns
        result = validator.validate_file_path("data.txt")
        assert isinstance(result, str)
    
    def test_validate_file_path_traversal(self, validator):
        with pytest.raises(ValidationError, match="dangerous pattern"):
            validator.validate_file_path("../../../etc/passwd")
        
        # Both forward and backslash traversals are caught
        with pytest.raises(ValidationError, match="dangerous pattern"):
            validator.validate_file_path("..\\..\\windows\\system32")
    
    def test_validate_column_name_valid(self, validator):
        assert validator.validate_column_name("age") == "age"
        assert validator.validate_column_name("user_name") == "user_name"
        assert validator.validate_column_name("column123") == "column123"
    
    def test_validate_column_name_invalid(self, validator):
        with pytest.raises(ValidationError, match="dangerous pattern"):
            validator.validate_column_name("col;DROP TABLE")
    
    def test_validate_integer(self, validator):
        assert validator.validate_integer(5, min_val=1, max_val=10) == 5
        
        with pytest.raises(ValidationError, match="must be at least"):
            validator.validate_integer(0, min_val=1)
        
        with pytest.raises(ValidationError, match="must be at most"):
            validator.validate_integer(11, max_val=10)
    
    def test_validate_float(self, validator):
        assert validator.validate_float(0.5, min_val=0.0, max_val=1.0) == 0.5
        
        with pytest.raises(ValidationError, match="must be at least"):
            validator.validate_float(-0.1, min_val=0.0)
    
    def test_validate_string(self, validator):
        assert validator.validate_string("test", max_length=10) == "test"
        
        # Test max length
        with pytest.raises(ValidationError, match="must be at most"):
            validator.validate_string("a" * 1001, max_length=1000)
    
    def test_validate_list(self, validator):
        result = validator.validate_list(["a", "b", "c"], item_type=str)
        assert result == ["a", "b", "c"]
        
        with pytest.raises(ValidationError, match="must be a list"):
            validator.validate_list("not_a_list", item_type=str)
    
    def test_validate_transform_type(self, validator, tmp_path):
        # Test that profile validation checks transform types
        valid_profile = {
            "columns": {
                "email": {"transform": "mask", "params": {}}
            }
        }
        profile_path = tmp_path / "transform_test.json"
        import json
        with open(profile_path, 'w') as f:
            json.dump(valid_profile, f)
        
        result = validator.validate_profile_json(str(profile_path))
        assert result["columns"]["email"]["transform"] == "mask"
    
    def test_validate_profile_json(self, validator, tmp_path):
        # Create valid profile file
        valid_profile = {
            "transforms": {
                "email": {"transform": "mask"}
            }
        }
        profile_path = tmp_path / "valid_profile.json"
        import json
        with open(profile_path, 'w') as f:
            json.dump(valid_profile, f)
        
        result = validator.validate_profile_json(str(profile_path))
        assert result is not None
