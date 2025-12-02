"""Differential Privacy implementation with noise injection"""
from typing import Optional, List, Dict, Any, Tuple
import random
import math
import pandas as pd
import numpy as np

class DifferentialPrivacy:
    """Implements differential privacy mechanisms"""
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize differential privacy handler
        
        Args:
            epsilon: Privacy budget (lower = more privacy, less accuracy)
            delta: Probability of privacy breach (typically very small)
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if delta < 0 or delta >= 1:
            raise ValueError("Delta must be in [0, 1)")
        
        self.epsilon = epsilon
        self.delta = delta
        self.privacy_budget_used = 0.0
    
    def add_laplace_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """
        Add Laplace noise for epsilon-differential privacy
        
        Args:
            value: Original value
            sensitivity: Global sensitivity of the query
            
        Returns:
            Noisy value
        """
        if self.privacy_budget_used >= self.epsilon:
            raise ValueError("Privacy budget exhausted")
        
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale)
        self.privacy_budget_used += self.epsilon
        
        return value + noise
    
    def add_gaussian_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """
        Add Gaussian noise for (epsilon, delta)-differential privacy
        
        Args:
            value: Original value
            sensitivity: Global sensitivity of the query
            
        Returns:
            Noisy value
        """
        if self.privacy_budget_used >= self.epsilon:
            raise ValueError("Privacy budget exhausted")
        
        # Calculate standard deviation for Gaussian mechanism
        sigma = (sensitivity * math.sqrt(2 * math.log(1.25 / self.delta))) / self.epsilon
        noise = np.random.normal(0, sigma)
        self.privacy_budget_used += self.epsilon
        
        return value + noise
    
    def noisy_count(self, count: int, sensitivity: float = 1.0) -> int:
        """
        Return differentially private count
        
        Args:
            count: True count
            sensitivity: Sensitivity (typically 1 for counting)
            
        Returns:
            Noisy count (non-negative integer)
        """
        noisy = self.add_laplace_noise(float(count), sensitivity)
        return max(0, int(round(noisy)))
    
    def noisy_sum(self, values: List[float], sensitivity: Optional[float] = None) -> float:
        """
        Return differentially private sum
        
        Args:
            values: List of values to sum
            sensitivity: Sensitivity (defaults to max absolute value)
            
        Returns:
            Noisy sum
        """
        true_sum = sum(values)
        if sensitivity is None:
            sensitivity = max(abs(v) for v in values) if values else 1.0
        
        return self.add_laplace_noise(true_sum, sensitivity)
    
    def noisy_mean(self, values: List[float], sensitivity: Optional[float] = None) -> float:
        """
        Return differentially private mean
        
        Args:
            values: List of values
            sensitivity: Sensitivity
            
        Returns:
            Noisy mean
        """
        if not values:
            return 0.0
        
        true_mean = sum(values) / len(values)
        if sensitivity is None:
            value_range = max(values) - min(values)
            sensitivity = value_range / len(values)
        
        return self.add_laplace_noise(true_mean, sensitivity)
    
    def randomized_response(self, true_value: bool, p: Optional[float] = None) -> bool:
        """
        Implement randomized response for boolean data
        
        Args:
            true_value: True boolean value
            p: Probability of telling truth (defaults based on epsilon)
            
        Returns:
            Randomized response
        """
        if p is None:
            # Set p based on epsilon for epsilon-differential privacy
            p = math.exp(self.epsilon) / (1 + math.exp(self.epsilon))
        
        if random.random() < p:
            return true_value
        else:
            return not true_value
    
    def apply_to_dataframe(self, df: pd.DataFrame, numeric_columns: List[str],
                          sensitivity: Optional[Dict[str, float]] = None) -> pd.DataFrame:
        """
        Apply differential privacy to numeric columns in DataFrame
        
        Args:
            df: Input DataFrame
            numeric_columns: Columns to add noise to
            sensitivity: Dictionary mapping column names to sensitivities
            
        Returns:
            DataFrame with noisy values
        """
        result_df = df.copy()
        
        if sensitivity is None:
            sensitivity = {}
        
        for col in numeric_columns:
            if col not in df.columns:
                continue
            
            col_sensitivity = sensitivity.get(col, 1.0)
            
            # Reset privacy budget for each column
            original_budget = self.privacy_budget_used
            self.privacy_budget_used = 0.0
            
            # Add noise to each value
            result_df[col] = df[col].apply(
                lambda x: self.add_laplace_noise(float(x), col_sensitivity) 
                if pd.notna(x) else x
            )
            
            # Restore budget tracking
            self.privacy_budget_used = original_budget + (self.epsilon / len(numeric_columns))
        
        return result_df
    
    def get_privacy_report(self) -> Dict[str, Any]:
        """Get privacy budget usage report"""
        return {
            'epsilon': self.epsilon,
            'delta': self.delta,
            'privacy_budget_used': self.privacy_budget_used,
            'privacy_budget_remaining': max(0, self.epsilon - self.privacy_budget_used),
            'budget_exhausted': self.privacy_budget_used >= self.epsilon
        }
    
    def reset_budget(self):
        """Reset privacy budget counter"""
        self.privacy_budget_used = 0.0


class AdaptiveDifferentialPrivacy:
    """Adaptive mechanism that adjusts noise based on data characteristics"""
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        self.epsilon = epsilon
        self.delta = delta
        self.dp = DifferentialPrivacy(epsilon, delta)
    
    def apply_adaptive_noise(self, df: pd.DataFrame, column: str,
                            min_value: Optional[float] = None,
                            max_value: Optional[float] = None) -> pd.DataFrame:
        """
        Apply adaptive noise based on column statistics
        
        Args:
            df: Input DataFrame
            column: Column to add noise to
            min_value: Minimum allowed value (for clamping)
            max_value: Maximum allowed value (for clamping)
            
        Returns:
            DataFrame with adaptive noise
        """
        result_df = df.copy()
        
        # Calculate adaptive sensitivity based on data range
        col_data = df[column].dropna()
        if len(col_data) == 0:
            return result_df
        
        data_min = col_data.min() if min_value is None else min_value
        data_max = col_data.max() if max_value is None else max_value
        sensitivity = (data_max - data_min) / len(col_data)
        
        # Apply noise
        result_df[column] = df[column].apply(
            lambda x: self._clamp(
                self.dp.add_laplace_noise(float(x), sensitivity),
                data_min, data_max
            ) if pd.notna(x) else x
        )
        
        return result_df
    
    def _clamp(self, value: float, min_val: float, max_val: float) -> float:
        """Clamp value to range"""
        return max(min_val, min(max_val, value))


def apply_differential_privacy_to_dataset(df: pd.DataFrame,
                                         numeric_columns: List[str],
                                         epsilon: float = 1.0,
                                         delta: float = 1e-5,
                                         sensitivities: Optional[Dict[str, float]] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Apply differential privacy to entire dataset
    
    Args:
        df: Input DataFrame
        numeric_columns: Columns to apply DP to
        epsilon: Privacy budget
        delta: Privacy parameter
        sensitivities: Optional custom sensitivities per column
        
    Returns:
        Tuple of (private DataFrame, privacy report)
    """
    dp = DifferentialPrivacy(epsilon=epsilon, delta=delta)
    result_df = dp.apply_to_dataframe(df, numeric_columns, sensitivities)
    report = dp.get_privacy_report()
    
    # Add comparison statistics
    report['comparison'] = {}
    for col in numeric_columns:
        if col in df.columns:
            original_mean = df[col].mean()
            noisy_mean = result_df[col].mean()
            report['comparison'][col] = {
                'original_mean': float(original_mean) if pd.notna(original_mean) else None,
                'noisy_mean': float(noisy_mean) if pd.notna(noisy_mean) else None,
                'absolute_error': abs(float(original_mean - noisy_mean)) if pd.notna(original_mean) and pd.notna(noisy_mean) else None
            }
    
    return result_df, report
