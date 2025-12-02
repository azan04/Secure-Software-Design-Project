"""Enhanced CLI for dataset anonymization with security and privacy features"""
import argparse
import os
import sys
import traceback
from typing import Optional
from anonykit import io, profile, transforms
from anonykit.validator import Validator, ValidationError
from anonykit.audit_logger import get_audit_logger
from anonykit.anonymization import KAnonymizer, LDiversityChecker, apply_k_anonymity_and_l_diversity
from anonykit.differential_privacy import DifferentialPrivacy, apply_differential_privacy_to_dataset
from anonykit.metrics import ComprehensiveReport, PrivacyMetrics, UtilityMetrics
from anonykit.rbac import get_rbac_manager, Permission

def process_csv(input_path: str, output_path: str, profile_path: str, 
                key: Optional[str] = None, user: Optional[str] = None,
                validate: bool = True, generate_report: bool = False):
    """
    Process CSV with anonymization
    
    Args:
        input_path: Input CSV file path
        output_path: Output CSV file path
        profile_path: Profile JSON path
        key: Secret key for HMAC transforms
        user: Username for audit logging
        validate: Whether to validate inputs
        generate_report: Whether to generate privacy/utility report
    """
    logger = get_audit_logger()
    validator = Validator()
    
    try:
        # Validate inputs if requested
        if validate:
            input_path = validator.validate_file_path(input_path, must_exist=True)
            output_path = validator.sanitize_output_path(output_path)
            profile_path = validator.validate_file_path(profile_path, must_exist=True)
        
        # Log data access
        logger.log_data_access(input_path, 'READ', user)
        
        # Load data
        df = io.read_csv(input_path)
        original_df = df.copy()  # Keep for metrics
        logger.log_data_access(input_path, 'LOADED', user, records_count=len(df))
        
        # Load and validate profile
        if validate:
            prof = validator.validate_profile_json(profile_path)
        else:
            prof = profile.load_profile(profile_path)
        
        logger.log_profile_load(profile_path, len(prof.get('columns', {})), user)
        
        key_bytes = key.encode('utf-8') if key else None
        
        # Apply column transformations
        cols = prof.get('columns', {})
        for col, spec in cols.items():
            if col not in df.columns:
                logger.log_security_event(
                    'COLUMN_NOT_FOUND',
                    f"Column '{col}' in profile not found in dataset",
                    'WARNING',
                    user
                )
                continue
            
            transform = spec.get('transform')
            params = spec.get('params', {})
            records_before = len(df)
            
            # Apply transformation
            if transform == 'mask':
                keep = params.get('keep_last', 4)
                df[col] = df[col].apply(lambda v: transforms.mask_value(v, keep_last=keep))
            
            elif transform == 'null':
                df[col] = df[col].apply(lambda v: transforms.null_value(v))
            
            elif transform == 'substitute':
                data_type = params.get('data_type', 'name')
                df[col] = df[col].apply(lambda v: transforms.substitute_value(v, data_type))
            
            elif transform == 'shuffle':
                df[col] = transforms.shuffle_column(df[col].tolist())
            
            elif transform == 'hash':
                salt = params.get('salt', prof.get('salt', ''))
                df[col] = df[col].apply(lambda v: transforms.salted_hash(v, salt))
            
            elif transform == 'hmac':
                out_len = params.get('out_len', 12)
                if not key_bytes:
                    error_msg = 'Error: hmac transform requires --key'
                    logger.log_error('MISSING_KEY', error_msg, profile_path, user)
                    print(error_msg)
                    sys.exit(1)
                df[col] = df[col].apply(lambda v: transforms.hmac_pseudonymize(v, key_bytes, out_len=out_len))
            
            elif transform == 'generalize_age':
                bins = params.get('bins')
                df[col] = df[col].apply(lambda v: transforms.generalize_age(v, bins=bins))
            
            elif transform == 'generalize_numeric':
                precision = params.get('precision', 0)
                df[col] = df[col].apply(lambda v: transforms.generalize_numeric(v, precision))
            
            elif transform == 'differential_privacy':
                epsilon = params.get('epsilon', 1.0)
                sensitivity = params.get('sensitivity', 1.0)
                df[col] = df[col].apply(lambda v: transforms.add_laplace_noise(v, epsilon, sensitivity))
            
            else:
                logger.log_security_event(
                    'UNKNOWN_TRANSFORM',
                    f"Unknown transform type '{transform}' for column '{col}'",
                    'WARNING',
                    user
                )
                continue
            
            # Log transformation
            logger.log_transformation(
                transform, col, params, len(df), user
            )
        
        # Apply k-anonymity and l-diversity if configured
        if 'k_anonymity' in prof or 'l_diversity' in prof:
            quasi_identifiers = prof.get('quasi_identifiers', [])
            sensitive_attr = prof.get('sensitive_attribute')
            k = prof.get('k_anonymity', {}).get('k', 3)
            l = prof.get('l_diversity', {}).get('l', 2)
            
            if quasi_identifiers and sensitive_attr:
                df, anon_report = apply_k_anonymity_and_l_diversity(
                    df, quasi_identifiers, sensitive_attr, k, l
                )
                
                logger.log_k_anonymity(
                    k, quasi_identifiers,
                    anon_report['k_anonymity']['satisfies'],
                    anon_report['k_anonymity']['min_group_size'],
                    input_path, user
                )
                
                logger.log_l_diversity(
                    l, sensitive_attr,
                    anon_report['l_diversity']['satisfies'],
                    anon_report['l_diversity']['min_diversity'],
                    input_path, user
                )
        
        # Apply differential privacy if configured
        if 'differential_privacy' in prof:
            dp_config = prof['differential_privacy']
            numeric_cols = dp_config.get('columns', [])
            epsilon = dp_config.get('epsilon', 1.0)
            delta = dp_config.get('delta', 1e-5)
            
            if numeric_cols:
                df, dp_report = apply_differential_privacy_to_dataset(
                    df, numeric_cols, epsilon, delta
                )
                
                logger.log_differential_privacy(
                    epsilon, delta, numeric_cols,
                    dp_report['privacy_budget_used'],
                    input_path, user
                )
        
        # Write output
        io.write_csv(df, output_path)
        logger.log_data_export(output_path, len(df), 'CSV', user)
        
        # Log anonymization summary
        logger.log_anonymization(
            'PROFILE_BASED',
            input_path,
            output_path,
            len(original_df),
            len(df),
            (len(original_df) - len(df)) / len(original_df) * 100 if len(original_df) > 0 else 0,
            prof,
            user
        )
        
        print(f'✓ Anonymization complete: {output_path}')
        print(f'  Original records: {len(original_df)}')
        print(f'  Anonymized records: {len(df)}')
        print(f'  Suppressed records: {len(original_df) - len(df)}')
        
        # Generate comprehensive report if requested
        if generate_report:
            quasi_ids = prof.get('quasi_identifiers', [])
            sensitive = prof.get('sensitive_attribute')
            numeric = prof.get('differential_privacy', {}).get('columns', [])
            
            report = ComprehensiveReport.generate_full_report(
                original_df, df, quasi_ids, sensitive, numeric
            )
            
            ComprehensiveReport.print_report(report)
            
            # Save report to JSON
            report_path = output_path.replace('.csv', '_report.json')
            import json
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f'\n✓ Report saved to: {report_path}')
    
    except ValidationError as e:
        logger.log_error('VALIDATION_ERROR', str(e), input_path, user)
        print(f'Validation Error: {e}')
        sys.exit(1)
    
    except Exception as e:
        logger.log_error('PROCESSING_ERROR', str(e), input_path, user, traceback.format_exc())
        print(f'Error: {e}')
        if '--debug' in sys.argv:
            traceback.print_exc()
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Anonymize CSV datasets with advanced privacy guarantees',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic anonymization
  python -m anonykit.cli -i data.csv -o anon.csv -p profile.json
  
  # With k-anonymity and reporting
  python -m anonykit.cli -i data.csv -o anon.csv -p profile.json --report
  
  # With user authentication
  python -m anonykit.cli -i data.csv -o anon.csv -p profile.json -u admin
  
  # Skip validation (faster, less secure)
  python -m anonykit.cli -i data.csv -o anon.csv -p profile.json --no-validate
        """
    )
    
    parser.add_argument('--input', '-i', required=True, 
                       help='Input CSV path')
    parser.add_argument('--output', '-o', required=True, 
                       help='Output CSV path')
    parser.add_argument('--profile', '-p', required=True, 
                       help='Profile JSON path')
    parser.add_argument('--key', '-k', required=False, 
                       help='Secret key for HMAC transforms')
    parser.add_argument('--user', '-u', required=False, 
                       help='Username for audit logging')
    parser.add_argument('--no-validate', action='store_true',
                       help='Skip input validation (faster but less secure)')
    parser.add_argument('--report', '-r', action='store_true',
                       help='Generate comprehensive privacy/utility report')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode with stack traces')
    
    args = parser.parse_args()
    
    # Check RBAC permissions if user provided
    if args.user:
        rbac = get_rbac_manager()
        if not rbac.check_permission(args.user, Permission.ANONYMIZE_DATA):
            print(f"Error: User '{args.user}' lacks permission to anonymize data")
            sys.exit(1)
    
    process_csv(
        args.input,
        args.output,
        args.profile,
        key=args.key,
        user=args.user,
        validate=not args.no_validate,
        generate_report=args.report
    )

if __name__ == '__main__':
    main()
