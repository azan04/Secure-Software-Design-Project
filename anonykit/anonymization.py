"""Anonymization algorithms: k-anonymity, l-diversity, t-closeness"""
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
from collections import Counter
import itertools

class KAnonymizer:
    """Implements k-anonymity for dataset protection"""
    
    def __init__(self, k: int = 3):
        """
        Initialize k-anonymizer
        
        Args:
            k: Minimum group size for k-anonymity
        """
        if k < 2:
            raise ValueError("k must be at least 2")
        self.k = k
    
    def check_k_anonymity(self, df: pd.DataFrame, quasi_identifiers: List[str]) -> Tuple[bool, int]:
        """
        Check if dataset satisfies k-anonymity
        
        Args:
            df: DataFrame to check
            quasi_identifiers: List of quasi-identifier column names
            
        Returns:
            Tuple of (satisfies_k_anonymity, minimum_group_size)
        """
        if not quasi_identifiers or len(df) == 0:
            return True, len(df)
        
        # Group by quasi-identifiers and count
        group_sizes = df.groupby(quasi_identifiers).size()
        
        if len(group_sizes) == 0:
            return True, 0
        
        min_group_size = group_sizes.min()
        
        # Handle NaN case
        if pd.isna(min_group_size):
            return True, 0
        
        return min_group_size >= self.k, int(min_group_size)
    
    def apply_k_anonymity(self, df: pd.DataFrame, quasi_identifiers: List[str], 
                         generalization_levels: Dict[str, int] = None) -> pd.DataFrame:
        """
        Apply k-anonymity through generalization and suppression
        
        Args:
            df: DataFrame to anonymize
            quasi_identifiers: Columns to generalize
            generalization_levels: Generalization level for each column
            
        Returns:
            k-anonymous DataFrame
        """
        result_df = df.copy()
        
        if generalization_levels is None:
            generalization_levels = {col: 1 for col in quasi_identifiers}
        
        # Apply generalization until k-anonymity is achieved
        satisfies_k, min_size = self.check_k_anonymity(result_df, quasi_identifiers)
        
        if satisfies_k:
            return result_df
        
        # Generalize columns progressively
        for col in quasi_identifiers:
            level = generalization_levels.get(col, 1)
            result_df = self._generalize_column(result_df, col, level)
            
            # Check if k-anonymity achieved
            satisfies_k, min_size = self.check_k_anonymity(result_df, quasi_identifiers)
            if satisfies_k:
                break
        
        # If still not k-anonymous, suppress small groups
        if not satisfies_k:
            result_df = self._suppress_small_groups(result_df, quasi_identifiers)
        
        return result_df
    
    def _generalize_column(self, df: pd.DataFrame, column: str, level: int) -> pd.DataFrame:
        """Generalize a column based on its data type"""
        result_df = df.copy()
        
        if pd.api.types.is_numeric_dtype(df[column]):
            # Numeric generalization: round to fewer decimal places
            result_df[column] = df[column].apply(lambda x: self._generalize_numeric(x, level))
        elif pd.api.types.is_string_dtype(df[column]):
            # String generalization: truncate or categorize
            result_df[column] = df[column].apply(lambda x: self._generalize_string(x, level))
        
        return result_df
    
    def _generalize_numeric(self, value: Any, level: int) -> Any:
        """Generalize numeric value"""
        if pd.isna(value):
            return value
        try:
            num = float(value)
            # Round to nearest 10^level
            factor = 10 ** level
            return round(num / factor) * factor
        except:
            return value
    
    def _generalize_string(self, value: Any, level: int) -> Any:
        """Generalize string value"""
        if pd.isna(value):
            return value
        s = str(value)
        if level == 0:
            return s
        # Truncate string
        keep_chars = max(1, len(s) - level)
        return s[:keep_chars] + '*' * (len(s) - keep_chars)
    
    def _suppress_small_groups(self, df: pd.DataFrame, quasi_identifiers: List[str]) -> pd.DataFrame:
        """Suppress records in groups smaller than k"""
        result_df = df.copy()
        
        # Identify groups and their sizes
        group_sizes = result_df.groupby(quasi_identifiers).size()
        small_groups = group_sizes[group_sizes < self.k].index
        
        # Create a mask for records to keep
        mask = ~result_df.set_index(quasi_identifiers).index.isin(small_groups)
        
        # Convert mask to array if needed
        if hasattr(mask, 'values'):
            mask_array = mask.values
        else:
            mask_array = mask
        
        return result_df[mask_array].reset_index(drop=True)
    
    def get_equivalence_classes(self, df: pd.DataFrame, quasi_identifiers: List[str]) -> Dict[Tuple, pd.DataFrame]:
        """Get equivalence classes (groups with same quasi-identifier values)"""
        classes = {}
        for key, group in df.groupby(quasi_identifiers):
            classes[key if isinstance(key, tuple) else (key,)] = group
        return classes


class LDiversityChecker:
    """Implements l-diversity checking for enhanced privacy"""
    
    def __init__(self, l: int = 2):
        """
        Initialize l-diversity checker
        
        Args:
            l: Minimum number of distinct sensitive values per equivalence class
        """
        if l < 1:
            raise ValueError("l must be at least 1")
        self.l = l
    
    def check_l_diversity(self, df: pd.DataFrame, quasi_identifiers: List[str], 
                         sensitive_attribute: str) -> Tuple[bool, int]:
        """
        Check if dataset satisfies l-diversity
        
        Args:
            df: DataFrame to check
            quasi_identifiers: Quasi-identifier columns
            sensitive_attribute: Sensitive attribute column
            
        Returns:
            Tuple of (satisfies_l_diversity, minimum_diversity)
        """
        if sensitive_attribute not in df.columns:
            raise ValueError(f"Sensitive attribute '{sensitive_attribute}' not found")
        
        if len(df) == 0:
            return True, 0
        
        # Get equivalence classes
        groups = df.groupby(quasi_identifiers)[sensitive_attribute]
        
        # Count distinct values in each group
        diversity_counts = groups.nunique()
        
        if len(diversity_counts) == 0:
            return True, 0
        
        min_diversity = diversity_counts.min()
        
        # Handle NaN case
        if pd.isna(min_diversity):
            return True, 0
        
        return min_diversity >= self.l, int(min_diversity)
    
    def apply_l_diversity(self, df: pd.DataFrame, quasi_identifiers: List[str],
                         sensitive_attribute: str) -> pd.DataFrame:
        """
        Enforce l-diversity through record suppression
        
        Args:
            df: DataFrame to enforce l-diversity on
            quasi_identifiers: Quasi-identifier columns
            sensitive_attribute: Sensitive attribute column
            
        Returns:
            l-diverse DataFrame
        """
        result_df = df.copy()
        
        # Get equivalence classes
        groups = result_df.groupby(quasi_identifiers)
        
        # Filter groups that don't satisfy l-diversity
        def group_satisfies_l_diversity(group):
            return group[sensitive_attribute].nunique() >= self.l
        
        # Keep only groups that satisfy l-diversity
        filtered_groups = groups.filter(group_satisfies_l_diversity)
        
        return filtered_groups.reset_index(drop=True)
    
    def get_diversity_report(self, df: pd.DataFrame, quasi_identifiers: List[str],
                            sensitive_attribute: str) -> Dict[str, Any]:
        """Generate diversity report for dataset"""
        groups = df.groupby(quasi_identifiers)[sensitive_attribute]
        diversity_counts = groups.nunique()
        
        return {
            'satisfies_l_diversity': diversity_counts.min() >= self.l,
            'min_diversity': int(diversity_counts.min()),
            'max_diversity': int(diversity_counts.max()),
            'avg_diversity': float(diversity_counts.mean()),
            'num_equivalence_classes': len(diversity_counts),
            'records_per_class': {
                'min': int(groups.size().min()),
                'max': int(groups.size().max()),
                'avg': float(groups.size().mean())
            }
        }


def apply_k_anonymity_and_l_diversity(df: pd.DataFrame, 
                                      quasi_identifiers: List[str],
                                      sensitive_attribute: str,
                                      k: int = 3,
                                      l: int = 2) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Apply both k-anonymity and l-diversity to a dataset
    
    Args:
        df: Input DataFrame
        quasi_identifiers: List of quasi-identifier columns
        sensitive_attribute: Sensitive attribute column
        k: k-anonymity parameter
        l: l-diversity parameter
        
    Returns:
        Tuple of (anonymized DataFrame, metrics report)
    """
    # Apply k-anonymity first
    k_anon = KAnonymizer(k=k)
    df_k_anon = k_anon.apply_k_anonymity(df, quasi_identifiers)
    
    # Check and apply l-diversity
    l_div = LDiversityChecker(l=l)
    df_final = l_div.apply_l_diversity(df_k_anon, quasi_identifiers, sensitive_attribute)
    
    # Generate report
    k_satisfies, k_min = k_anon.check_k_anonymity(df_final, quasi_identifiers)
    l_satisfies, l_min = l_div.check_l_diversity(df_final, quasi_identifiers, sensitive_attribute)
    
    report = {
        'original_records': len(df),
        'anonymized_records': len(df_final),
        'records_suppressed': len(df) - len(df_final),
        'suppression_rate': (len(df) - len(df_final)) / len(df) * 100 if len(df) > 0 else 0,
        'k_anonymity': {
            'k': k,
            'satisfies': k_satisfies,
            'min_group_size': k_min
        },
        'l_diversity': {
            'l': l,
            'satisfies': l_satisfies,
            'min_diversity': l_min
        }
    }
    
    return df_final, report
