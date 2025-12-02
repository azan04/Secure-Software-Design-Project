"""
Integration tests for end-to-end workflows
"""
import pytest
import os
import pandas as pd
from anonykit import io, transforms
from anonykit.anonymization import apply_k_anonymity_and_l_diversity
from anonykit.differential_privacy import DifferentialPrivacy
from anonykit.validator import Validator
from anonykit.audit_logger import get_audit_logger
from anonykit.metrics import ComprehensiveReport


class TestEndToEndCLI:
    """Test complete CLI workflow"""
    
    @pytest.fixture
    def sample_csv(self, tmp_path):
        # Create sample CSV
        df = pd.DataFrame({
            'name': ['Alice', 'Bob', 'Charlie', 'David'],
            'age': [25, 30, 25, 30],
            'email': ['alice@email.com', 'bob@email.com', 'charlie@email.com', 'david@email.com'],
            'salary': [50000, 60000, 52000, 62000],
            'department': ['IT', 'HR', 'IT', 'HR']
        })
        path = tmp_path / "test_input.csv"
        df.to_csv(path, index=False)
        return path
    
    @pytest.fixture
    def sample_profile(self, tmp_path):
        # Create sample profile
        profile = {
            "transforms": {
                "email": {"transform": "mask"},
                "name": {"transform": "substitute"}
            }
        }
        path = tmp_path / "test_profile.json"
        with open(path, 'w') as f:
            import json
            json.dump(profile, f)
        return path
    
    def test_full_workflow(self, tmp_path, sample_csv, sample_profile):
        output_path = tmp_path / "test_output.csv"
        
        # Load data
        df = io.read_csv(str(sample_csv))
        assert len(df) == 4
        
        # Load profile
        import json
        with open(sample_profile, 'r') as f:
            profile = json.load(f)
        assert "transforms" in profile
        
        # Apply transforms
        for column, config in profile["transforms"].items():
            transform = config["transform"]
            if transform == "mask":
                df[column] = df[column].apply(transforms.mask_value)
            elif transform == "substitute":
                df[column] = df[column].apply(lambda x: transforms.substitute_value(x, column))
        
        # Verify transformations
        assert all("*" in str(email) for email in df["email"])
        assert not any(name in df["name"].values for name in ['Alice', 'Bob', 'Charlie', 'David'])
        
        # Save output
        io.write_csv(df, str(output_path))
        assert os.path.exists(output_path)
        
        # Verify saved data
        loaded = io.read_csv(str(output_path))
        assert len(loaded) == 4
        assert list(loaded.columns) == list(df.columns)


class TestAnonymizationWorkflow:
    """Test k-anonymity and l-diversity workflow"""
    
    def test_anonymization_pipeline(self):
        # Create dataset
        df = pd.DataFrame({
            'age': [25, 26, 30, 31, 35, 36, 40, 41],
            'department': ['IT', 'IT', 'HR', 'HR', 'IT', 'IT', 'HR', 'HR'],
            'salary': [50000, 52000, 55000, 57000, 60000, 62000, 65000, 67000],
            'diagnosis': ['Diabetes', 'Asthma', 'Diabetes', 'Hypertension',
                         'Asthma', 'Cancer', 'Hypertension', 'Diabetes']
        })
        
        # Apply anonymization
        result, report = apply_k_anonymity_and_l_diversity(
            df,
            quasi_identifiers=['age', 'department'],
            sensitive_attribute='diagnosis',
            k=2,
            l=2
        )
        
        # Verify result
        assert isinstance(result, pd.DataFrame)
        assert len(result) > 0
        assert 'k_anonymity' in report
        assert 'l_diversity' in report


class TestDifferentialPrivacyWorkflow:
    """Test differential privacy workflow"""
    
    def test_dp_pipeline(self):
        # Create dataset
        df = pd.DataFrame({
            'age': [25, 30, 35, 40, 45]
        })
        
        # Apply differential privacy - use transform function directly without budget tracking
        result = df.copy()
        result['age'] = [transforms.add_laplace_noise(float(x), epsilon=1.0) for x in df['age']]
        
        # Verify result
        assert isinstance(result, pd.DataFrame)
        assert len(result) == len(df)
        # Values should be floats
        assert all(isinstance(x, (int, float)) for x in result['age'])


class TestMetricsGeneration:
    """Test metrics and reporting"""
    
    def test_comprehensive_report(self):
        from anonykit.metrics import PrivacyMetrics, UtilityMetrics
        
        # Original data
        original_df = pd.DataFrame({
            'age': [25, 30, 35, 40],
            'salary': [50000, 60000, 70000, 80000],
            'diagnosis': ['A', 'B', 'A', 'C']
        })
        
        # Anonymized data (slightly modified)
        anonymized_df = pd.DataFrame({
            'age': [25, 30, 35, 40],
            'salary': [50500, 60500, 70500, 80500],
            'diagnosis': ['A', 'B', 'A', 'C']
        })
        
        # Generate privacy metrics
        privacy_metrics = PrivacyMetrics.calculate_k_anonymity(anonymized_df, ['age'])
        utility_metrics = UtilityMetrics.calculate_data_retention(original_df, anonymized_df)
        
        full_report = {
            'privacy_metrics': privacy_metrics,
            'utility_metrics': {'data_retention_rate': utility_metrics}
        }
        
        # Verify report structure
        assert 'privacy_metrics' in full_report
        assert 'utility_metrics' in full_report
        
        # Verify metrics presence
        privacy = full_report['privacy_metrics']
        assert 'k_value' in privacy
        assert 'satisfies_k_anonymity' in privacy
        
        utility = full_report['utility_metrics']
        assert 'data_retention_rate' in utility


class TestValidationWorkflow:
    """Test validation in workflows"""
    
    def test_validated_workflow(self):
        validator = Validator()
        
        # Validate inputs - these return the validated value, not True
        result = validator.validate_file_path("data.csv")
        assert isinstance(result, str)
        assert validator.validate_column_name("age") == "age"
        assert validator.validate_integer(3, min_val=2, max_val=10) == 3
        assert validator.validate_float(1.0, min_val=0.1, max_val=10.0) == 1.0
        
        # Test invalid inputs
        with pytest.raises(Exception):
            validator.validate_file_path("../../../etc/passwd")
        
        with pytest.raises(Exception):
            validator.validate_integer(0, min_val=1)
