"""
Unit tests for anonymization techniques
"""
import pytest
import pandas as pd
from anonykit.anonymization import KAnonymizer, LDiversityChecker, apply_k_anonymity_and_l_diversity


class TestKAnonymity:
    """Test k-anonymity implementation"""
    
    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            'age': [25, 25, 30, 30, 35, 35, 40, 40],
            'department': ['IT', 'IT', 'HR', 'HR', 'IT', 'IT', 'HR', 'HR'],
            'salary': [50000, 52000, 55000, 57000, 60000, 62000, 65000, 67000],
            'name': ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
        })
    
    def test_check_k_anonymity_pass(self, sample_df):
        anonymizer = KAnonymizer(k=2)
        is_anonymous, min_group = anonymizer.check_k_anonymity(sample_df, ['age', 'department'])
        assert is_anonymous == True
        assert min_group >= 2
    
    def test_check_k_anonymity_fail(self, sample_df):
        # Add unique record
        df = pd.concat([sample_df, pd.DataFrame({
            'age': [50],
            'department': ['Marketing'],
            'salary': [70000],
            'name': ['I']
        })], ignore_index=True)
        
        anonymizer = KAnonymizer(k=2)
        is_anonymous, min_group = anonymizer.check_k_anonymity(df, ['age', 'department'])
        assert is_anonymous == False
        assert min_group == 1
    
    def test_apply_k_anonymity(self, sample_df):
        anonymizer = KAnonymizer(k=2)
        result = anonymizer.apply_k_anonymity(sample_df, ['age', 'department'])
        
        # Check that result still has k-anonymity
        is_anonymous, _ = anonymizer.check_k_anonymity(result, ['age', 'department'])
        assert is_anonymous == True
    
    def test_empty_dataframe(self):
        df = pd.DataFrame()
        anonymizer = KAnonymizer(k=2)
        is_anonymous, min_group = anonymizer.check_k_anonymity(df, ['age'])
        assert is_anonymous is True
        assert min_group == 0


class TestLDiversity:
    """Test l-diversity implementation"""
    
    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            'age': [25, 25, 30, 30, 35, 35, 40, 40],
            'department': ['IT', 'IT', 'HR', 'HR', 'IT', 'IT', 'HR', 'HR'],
            'diagnosis': ['Diabetes', 'Asthma', 'Diabetes', 'Hypertension', 
                         'Asthma', 'Cancer', 'Hypertension', 'Diabetes']
        })
    
    def test_check_l_diversity_pass(self, sample_df):
        checker = LDiversityChecker(l=2)
        is_diverse, min_diversity = checker.check_l_diversity(
            sample_df, ['age', 'department'], 'diagnosis'
        )
        assert is_diverse == True
        assert min_diversity >= 2
    
    def test_check_l_diversity_fail(self):
        # All same diagnosis in a group
        df = pd.DataFrame({
            'age': [25, 25],
            'department': ['IT', 'IT'],
            'diagnosis': ['Diabetes', 'Diabetes']
        })
        
        checker = LDiversityChecker(l=2)
        is_diverse, min_diversity = checker.check_l_diversity(
            df, ['age', 'department'], 'diagnosis'
        )
        assert is_diverse == False
        assert min_diversity == 1


class TestCombinedAnonymization:
    """Test combined k-anonymity and l-diversity"""
    
    def test_apply_combined(self):
        df = pd.DataFrame({
            'age': [25, 26, 30, 31, 35, 36, 40, 41],
            'department': ['IT', 'IT', 'HR', 'HR', 'IT', 'IT', 'HR', 'HR'],
            'diagnosis': ['Diabetes', 'Asthma', 'Diabetes', 'Hypertension', 
                         'Asthma', 'Cancer', 'Hypertension', 'Diabetes'],
            'name': ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
        })
        
        result, report = apply_k_anonymity_and_l_diversity(
            df, ['age', 'department'], 'diagnosis', k=2, l=2
        )
        
        assert isinstance(result, pd.DataFrame)
        assert len(result) <= len(df)  # May suppress some records
        assert 'k_anonymity' in report
        assert 'l_diversity' in report
