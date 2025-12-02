"""Privacy and utility metrics for assessing anonymization quality"""
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import numpy as np
from collections import Counter
import math

class PrivacyMetrics:
    """Calculate privacy metrics for anonymized datasets"""
    
    @staticmethod
    def calculate_k_anonymity(df: pd.DataFrame, quasi_identifiers: List[str]) -> Dict[str, Any]:
        """
        Calculate k-anonymity metrics
        
        Args:
            df: Anonymized DataFrame
            quasi_identifiers: List of quasi-identifier columns
            
        Returns:
            Dictionary with k-anonymity metrics
        """
        if len(df) == 0:
            return {
                'k_value': 0,
                'satisfies_k_anonymity': False,
                'min_group_size': 0,
                'max_group_size': 0,
                'avg_group_size': 0.0,
                'num_groups': 0,
                'group_size_distribution': {}
            }
        
        if not quasi_identifiers:
            return {
                'k_value': len(df),
                'satisfies_k_anonymity': True,
                'min_group_size': len(df),
                'max_group_size': len(df),
                'avg_group_size': len(df),
                'num_groups': 1
            }
        
        # Group by quasi-identifiers
        groups = df.groupby(quasi_identifiers).size()
        
        if len(groups) == 0:
            return {
                'k_value': 0,
                'satisfies_k_anonymity': False,
                'min_group_size': 0,
                'max_group_size': 0,
                'avg_group_size': 0.0,
                'num_groups': 0
            }
        
        return {
            'k_value': int(groups.min()),
            'satisfies_k_anonymity': groups.min() >= 2,
            'min_group_size': int(groups.min()),
            'max_group_size': int(groups.max()),
            'avg_group_size': float(groups.mean()),
            'num_groups': len(groups),
            'group_size_distribution': dict(Counter(groups.values))
        }
    
    @staticmethod
    def calculate_l_diversity(df: pd.DataFrame, quasi_identifiers: List[str],
                             sensitive_attribute: str, l: int = 2) -> Dict[str, Any]:
        """
        Calculate l-diversity metrics
        
        Args:
            df: Anonymized DataFrame
            quasi_identifiers: Quasi-identifier columns
            sensitive_attribute: Sensitive attribute column
            l: Required diversity level
            
        Returns:
            Dictionary with l-diversity metrics
        """
        if sensitive_attribute not in df.columns:
            return {'error': f"Sensitive attribute '{sensitive_attribute}' not found"}
        
        groups = df.groupby(quasi_identifiers)[sensitive_attribute]
        diversity_counts = groups.nunique()
        
        return {
            'l_value': int(diversity_counts.min()),
            'satisfies_l_diversity': diversity_counts.min() >= l,
            'required_l': l,
            'min_diversity': int(diversity_counts.min()),
            'max_diversity': int(diversity_counts.max()),
            'avg_diversity': float(diversity_counts.mean()),
            'groups_satisfying_l': int((diversity_counts >= l).sum()),
            'groups_not_satisfying_l': int((diversity_counts < l).sum())
        }
    
    @staticmethod
    def calculate_entropy(df: pd.DataFrame, column: str) -> float:
        """
        Calculate Shannon entropy of a column
        
        Args:
            df: DataFrame
            column: Column name
            
        Returns:
            Entropy value
        """
        if column not in df.columns:
            return 0.0
        
        values = df[column].dropna()
        if len(values) == 0:
            return 0.0
        
        # Calculate probabilities
        value_counts = values.value_counts(normalize=True)
        
        # Calculate entropy
        entropy = -sum(p * math.log2(p) for p in value_counts if p > 0)
        
        return float(entropy)
    
    @staticmethod
    def calculate_distinctness(df: pd.DataFrame, quasi_identifiers: List[str]) -> float:
        """
        Calculate average distinctness (inverse of equivalence class size)
        
        Args:
            df: DataFrame
            quasi_identifiers: Quasi-identifier columns
            
        Returns:
            Average distinctness score (0-1, lower is better for privacy)
        """
        if not quasi_identifiers or len(df) == 0:
            return 0.0
        
        groups = df.groupby(quasi_identifiers).size()
        avg_group_size = groups.mean()
        
        # Distinctness is inverse of group size, normalized
        distinctness = 1.0 / avg_group_size if avg_group_size > 0 else 0.0
        
        return float(distinctness)
    
    @staticmethod
    def estimate_reidentification_risk(df: pd.DataFrame, 
                                      quasi_identifiers: List[str]) -> Dict[str, Any]:
        """
        Estimate re-identification risk based on equivalence class sizes
        
        Args:
            df: Anonymized DataFrame
            quasi_identifiers: Quasi-identifier columns
            
        Returns:
            Dictionary with risk metrics
        """
        if not quasi_identifiers or len(df) == 0:
            return {
                'avg_risk': 0.0,
                'max_risk': 0.0,
                'records_at_high_risk': 0,
                'records_at_medium_risk': 0,
                'records_at_low_risk': len(df)
            }
        
        # Calculate risk for each equivalence class
        group_sizes = df.groupby(quasi_identifiers).size()
        
        # Risk is 1/group_size (probability of re-identification)
        risks = 1.0 / group_sizes
        
        # Map risks back to records
        df_with_risk = df.copy()
        df_with_risk['_risk'] = df_with_risk.groupby(quasi_identifiers).transform('size')
        df_with_risk['_risk'] = 1.0 / df_with_risk['_risk']
        
        # Categorize risk levels
        high_risk_threshold = 0.33  # >33% chance
        medium_risk_threshold = 0.10  # 10-33% chance
        
        high_risk = (df_with_risk['_risk'] > high_risk_threshold).sum()
        medium_risk = ((df_with_risk['_risk'] > medium_risk_threshold) & 
                      (df_with_risk['_risk'] <= high_risk_threshold)).sum()
        low_risk = (df_with_risk['_risk'] <= medium_risk_threshold).sum()
        
        return {
            'avg_risk': float(risks.mean()),
            'max_risk': float(risks.max()),
            'min_risk': float(risks.min()),
            'records_at_high_risk': int(high_risk),
            'records_at_medium_risk': int(medium_risk),
            'records_at_low_risk': int(low_risk),
            'high_risk_percentage': float(high_risk / len(df) * 100),
            'medium_risk_percentage': float(medium_risk / len(df) * 100),
            'low_risk_percentage': float(low_risk / len(df) * 100)
        }


class UtilityMetrics:
    """Calculate utility metrics to assess data quality after anonymization"""
    
    @staticmethod
    def calculate_information_loss(original_df: pd.DataFrame, 
                                   anonymized_df: pd.DataFrame,
                                   columns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Calculate information loss due to anonymization
        
        Args:
            original_df: Original DataFrame
            anonymized_df: Anonymized DataFrame
            columns: Columns to assess (default: all common columns)
            
        Returns:
            Dictionary with information loss metrics
        """
        if columns is None:
            columns = list(set(original_df.columns) & set(anonymized_df.columns))
        
        results = {}
        total_loss = 0.0
        
        for col in columns:
            if col not in original_df.columns or col not in anonymized_df.columns:
                continue
            
            # Calculate entropy before and after
            original_entropy = PrivacyMetrics.calculate_entropy(original_df, col)
            anonymized_entropy = PrivacyMetrics.calculate_entropy(anonymized_df, col)
            
            # Information loss as percentage
            if original_entropy > 0:
                loss = (original_entropy - anonymized_entropy) / original_entropy * 100
            else:
                loss = 0.0
            
            results[col] = {
                'original_entropy': float(original_entropy),
                'anonymized_entropy': float(anonymized_entropy),
                'information_loss_pct': float(loss)
            }
            
            total_loss += loss
        
        avg_loss = total_loss / len(results) if results else 0.0
        
        return {
            'per_column': results,
            'avg_information_loss_pct': float(avg_loss),
            'columns_analyzed': len(results)
        }
    
    @staticmethod
    def calculate_numeric_error(original_df: pd.DataFrame,
                               anonymized_df: pd.DataFrame,
                               numeric_columns: List[str]) -> Dict[str, Any]:
        """
        Calculate error metrics for numeric columns (e.g., after adding noise)
        
        Args:
            original_df: Original DataFrame
            anonymized_df: Anonymized DataFrame
            numeric_columns: Numeric columns to analyze
            
        Returns:
            Dictionary with error metrics
        """
        results = {}
        
        for col in numeric_columns:
            if col not in original_df.columns or col not in anonymized_df.columns:
                continue
            
            orig = original_df[col].dropna()
            anon = anonymized_df[col].dropna()
            
            if len(orig) == 0 or len(anon) == 0:
                continue
            
            # Calculate various error metrics
            orig_mean = orig.mean()
            anon_mean = anon.mean()
            
            abs_error = abs(orig_mean - anon_mean)
            rel_error = (abs_error / orig_mean * 100) if orig_mean != 0 else 0.0
            
            # Standard deviation comparison
            orig_std = orig.std()
            anon_std = anon.std()
            
            results[col] = {
                'original_mean': float(orig_mean),
                'anonymized_mean': float(anon_mean),
                'absolute_error': float(abs_error),
                'relative_error_pct': float(rel_error),
                'original_std': float(orig_std),
                'anonymized_std': float(anon_std)
            }
        
        return results
    
    @staticmethod
    def calculate_data_retention(original_df: pd.DataFrame,
                                anonymized_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate how much data was retained vs suppressed
        
        Args:
            original_df: Original DataFrame
            anonymized_df: Anonymized DataFrame
            
        Returns:
            Dictionary with retention metrics
        """
        orig_records = len(original_df)
        anon_records = len(anonymized_df)
        suppressed = orig_records - anon_records
        
        return {
            'original_records': orig_records,
            'anonymized_records': anon_records,
            'suppressed_records': suppressed,
            'retention_rate_pct': float(anon_records / orig_records * 100) if orig_records > 0 else 0.0,
            'suppression_rate_pct': float(suppressed / orig_records * 100) if orig_records > 0 else 0.0
        }


class ComprehensiveReport:
    """Generate comprehensive privacy and utility reports"""
    
    @staticmethod
    def generate_full_report(original_df: pd.DataFrame,
                           anonymized_df: pd.DataFrame,
                           quasi_identifiers: List[str],
                           sensitive_attribute: Optional[str] = None,
                           numeric_columns: Optional[List[str]] = None,
                           k: int = 3,
                           l: int = 2) -> Dict[str, Any]:
        """
        Generate comprehensive report with all metrics
        
        Args:
            original_df: Original DataFrame
            anonymized_df: Anonymized DataFrame
            quasi_identifiers: Quasi-identifier columns
            sensitive_attribute: Sensitive attribute for l-diversity
            numeric_columns: Numeric columns for error analysis
            k: Required k-anonymity value
            l: Required l-diversity value
            
        Returns:
            Comprehensive report dictionary
        """
        report = {
            'timestamp': pd.Timestamp.now().isoformat(),
            'privacy_metrics': {},
            'utility_metrics': {},
            'summary': {}
        }
        
        # Privacy metrics
        privacy = PrivacyMetrics()
        report['privacy_metrics']['k_anonymity'] = privacy.calculate_k_anonymity(
            anonymized_df, quasi_identifiers
        )
        
        if sensitive_attribute:
            report['privacy_metrics']['l_diversity'] = privacy.calculate_l_diversity(
                anonymized_df, quasi_identifiers, sensitive_attribute, l
            )
        
        report['privacy_metrics']['reidentification_risk'] = privacy.estimate_reidentification_risk(
            anonymized_df, quasi_identifiers
        )
        
        # Utility metrics
        utility = UtilityMetrics()
        report['utility_metrics']['data_retention'] = utility.calculate_data_retention(
            original_df, anonymized_df
        )
        
        report['utility_metrics']['information_loss'] = utility.calculate_information_loss(
            original_df, anonymized_df
        )
        
        if numeric_columns:
            report['utility_metrics']['numeric_error'] = utility.calculate_numeric_error(
                original_df, anonymized_df, numeric_columns
            )
        
        # Summary
        k_satisfies = report['privacy_metrics']['k_anonymity'].get('satisfies_k_anonymity', False)
        l_satisfies = report['privacy_metrics'].get('l_diversity', {}).get('satisfies_l_diversity', True)
        
        report['summary'] = {
            'privacy_requirements_met': k_satisfies and l_satisfies,
            'k_anonymity_satisfied': k_satisfies,
            'l_diversity_satisfied': l_satisfies,
            'data_retention_pct': report['utility_metrics']['data_retention']['retention_rate_pct'],
            'avg_reidentification_risk': report['privacy_metrics']['reidentification_risk']['avg_risk'],
            'recommendation': ComprehensiveReport._generate_recommendation(report)
        }
        
        return report
    
    @staticmethod
    def _generate_recommendation(report: Dict[str, Any]) -> str:
        """Generate recommendations based on metrics"""
        recommendations = []
        
        # Check k-anonymity
        if not report['privacy_metrics']['k_anonymity'].get('satisfies_k_anonymity'):
            recommendations.append(
                "CRITICAL: k-anonymity not satisfied. Increase generalization or suppression."
            )
        
        # Check l-diversity
        if 'l_diversity' in report['privacy_metrics']:
            if not report['privacy_metrics']['l_diversity'].get('satisfies_l_diversity'):
                recommendations.append(
                    "WARNING: l-diversity not satisfied. Consider data augmentation or suppression."
                )
        
        # Check re-identification risk
        high_risk_pct = report['privacy_metrics']['reidentification_risk'].get('high_risk_percentage', 0)
        if high_risk_pct > 10:
            recommendations.append(
                f"ALERT: {high_risk_pct:.1f}% of records at high re-identification risk."
            )
        
        # Check data retention
        retention = report['utility_metrics']['data_retention']['retention_rate_pct']
        if retention < 50:
            recommendations.append(
                f"WARNING: Low data retention ({retention:.1f}%). Consider less aggressive anonymization."
            )
        
        if not recommendations:
            return "All privacy requirements met with acceptable utility. Dataset is ready for sharing."
        
        return " ".join(recommendations)
    
    @staticmethod
    def print_report(report: Dict[str, Any]):
        """Print formatted report to console"""
        print("=" * 80)
        print("ANONYMIZATION REPORT")
        print("=" * 80)
        print(f"\nTimestamp: {report['timestamp']}")
        
        print("\n--- PRIVACY METRICS ---")
        print(f"\nK-Anonymity:")
        k_metrics = report['privacy_metrics']['k_anonymity']
        print(f"  k-value: {k_metrics.get('k_value')}")
        print(f"  Status: {'✓ PASS' if k_metrics.get('satisfies_k_anonymity') else '✗ FAIL'}")
        print(f"  Min group size: {k_metrics.get('min_group_size')}")
        print(f"  Avg group size: {k_metrics.get('avg_group_size', 0):.2f}")
        
        if 'l_diversity' in report['privacy_metrics']:
            print(f"\nL-Diversity:")
            l_metrics = report['privacy_metrics']['l_diversity']
            print(f"  l-value: {l_metrics.get('l_value')}")
            print(f"  Status: {'✓ PASS' if l_metrics.get('satisfies_l_diversity') else '✗ FAIL'}")
        
        print(f"\nRe-identification Risk:")
        risk = report['privacy_metrics']['reidentification_risk']
        print(f"  Average risk: {risk.get('avg_risk', 0):.2%}")
        print(f"  High risk records: {risk.get('high_risk_percentage', 0):.1f}%")
        print(f"  Low risk records: {risk.get('low_risk_percentage', 0):.1f}%")
        
        print("\n--- UTILITY METRICS ---")
        retention = report['utility_metrics']['data_retention']
        print(f"\nData Retention:")
        print(f"  Original records: {retention.get('original_records')}")
        print(f"  Retained records: {retention.get('anonymized_records')}")
        print(f"  Retention rate: {retention.get('retention_rate_pct', 0):.2f}%")
        
        print("\n--- SUMMARY ---")
        summary = report['summary']
        print(f"\nPrivacy Requirements Met: {'✓ YES' if summary.get('privacy_requirements_met') else '✗ NO'}")
        print(f"\nRecommendation: {summary.get('recommendation')}")
        print("=" * 80)
