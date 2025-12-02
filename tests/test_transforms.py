"""
Unit tests for transformation functions
"""
import pytest
import pandas as pd
from anonykit import transforms


class TestMasking:
    """Test masking transformations"""
    
    def test_mask_value_default(self):
        result = transforms.mask_value("john.doe@email.com")
        # Keeps last 4 chars
        assert result.endswith(".com")
        assert "*" in result
    
    def test_mask_value_custom_char(self):
        result = transforms.mask_value("john.doe@email.com", mask_char="#")
        # Keeps last 4 chars
        assert result.endswith(".com")
        assert "#" in result
    
    def test_mask_value_empty(self):
        result = transforms.mask_value("")
        assert result == ""
    
    def test_mask_column(self):
        # Test masking on list of values
        emails = ["test@email.com", "user@domain.com"]
        results = [transforms.mask_value(e) for e in emails]
        assert all("*" in val for val in results)


class TestSubstitution:
    """Test substitution transformations"""
    
    def test_substitute_value(self):
        result = transforms.substitute_value("John Smith", "name")
        assert result != "John Smith"
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_substitute_email(self):
        result = transforms.substitute_value("test@email.com", "email")
        assert "@" in result
        assert result != "test@email.com"


class TestGeneralization:
    """Test generalization transformations"""
    
    def test_generalize_age(self):
        # Use list of bins
        assert transforms.generalize_age(25, [0, 20, 30, 40, 50, 120]) == "20-29"
        assert transforms.generalize_age(45, [0, 20, 30, 40, 50, 120]) == "40-49"
        assert transforms.generalize_age(8, [0, 20, 30, 40, 50, 120]) == "0-19"
    
    def test_generalize_numeric(self):
        # Test precision rounding
        assert transforms.generalize_numeric(55555.55, 0) == 55555.0
        assert transforms.generalize_numeric(55555.55, 1) == 55555.6
        assert transforms.generalize_numeric(55555.55, 2) == 55555.55


class TestHashing:
    """Test hashing transformations"""
    
    def test_salted_hash_consistency(self):
        salt = "test_salt"
        result1 = transforms.salted_hash("test_value", salt)
        result2 = transforms.salted_hash("test_value", salt)
        assert result1 == result2
    
    def test_salted_hash_different_values(self):
        salt = "test_salt"
        result1 = transforms.salted_hash("value1", salt)
        result2 = transforms.salted_hash("value2", salt)
        assert result1 != result2
    
    def test_hmac_pseudonymize(self):
        key = b"secret_key"  # Must be bytes
        result1 = transforms.hmac_pseudonymize("123-45-6789", key)
        result2 = transforms.hmac_pseudonymize("123-45-6789", key)
        assert result1 == result2


class TestShuffle:
    """Test shuffle transformation"""
    
    def test_shuffle_column(self):
        original = [1, 2, 3, 4, 5]
        result = transforms.shuffle_column(original)
        
        # Same elements but potentially different order
        assert sorted(original) == sorted(result)
        assert original != result or len(original) <= 1  # Might be same if length 1


class TestNulling:
    """Test null transformation"""
    
    def test_null_value(self):
        assert pd.isna(transforms.null_value("any_value"))
    
    def test_null_column(self):
        # Test nulling on list of values
        values = ["a", "b", "c"]
        results = [transforms.null_value(v) for v in values]
        assert all(r is None for r in results)


class TestDifferentialPrivacy:
    """Test differential privacy noise addition"""
    
    def test_add_laplace_noise(self):
        original = 100.0
        result = transforms.add_laplace_noise(original, epsilon=1.0)
        assert isinstance(result, float)
        # Should be close but not exact
        assert abs(result - original) < 50  # Reasonable bound
    
    def test_add_laplace_noise_column(self):
        # Test adding noise to values
        original = [50000.0, 60000.0, 70000.0]
        results = [transforms.add_laplace_noise(v, epsilon=1.0) for v in original]
        # Check they are floats and within reasonable range
        for orig, noisy in zip(original, results):
            assert isinstance(noisy, float)
            assert abs(noisy - orig) < orig * 2.0  # Within 200%
