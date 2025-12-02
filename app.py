"""AnonyKit Web Application - Flask-based frontend for dataset anonymization"""
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import json
import pandas as pd
from datetime import datetime, timedelta
import traceback
from functools import wraps
from collections import defaultdict

from anonykit import io, transforms
from anonykit.validator import Validator, ValidationError
from anonykit.audit_logger import get_audit_logger
from anonykit.anonymization import apply_k_anonymity_and_l_diversity
from anonykit.differential_privacy import DifferentialPrivacy
from anonykit.metrics import ComprehensiveReport
from anonykit.rbac import get_rbac_manager, Permission

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Rate limiting configuration
app.config['RATELIMIT_STORAGE_URL'] = 'memory://'
app.config['RATELIMIT_STRATEGY'] = 'fixed-window'
app.config['RATELIMIT_HEADERS_ENABLED'] = True

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Initialize managers
logger = get_audit_logger()
rbac = get_rbac_manager()
validator = Validator()

# Brute force protection - track failed login attempts
login_attempts = defaultdict(lambda: {'count': 0, 'locked_until': None})
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

def is_account_locked(username):
    """Check if account is locked due to failed login attempts"""
    attempt_data = login_attempts.get(username)
    if attempt_data and attempt_data['locked_until']:
        if datetime.now() < attempt_data['locked_until']:
            return True
        else:
            # Lockout expired, reset
            login_attempts[username] = {'count': 0, 'locked_until': None}
    return False

def record_failed_login(username):
    """Record failed login attempt and lock account if threshold exceeded"""
    login_attempts[username]['count'] += 1
    
    if login_attempts[username]['count'] >= MAX_LOGIN_ATTEMPTS:
        login_attempts[username]['locked_until'] = datetime.now() + LOCKOUT_DURATION
        logger.log_security_event(
            'ACCOUNT_LOCKED',
            f'Account locked due to {MAX_LOGIN_ATTEMPTS} failed login attempts',
            'WARNING',
            username
        )
        return True
    return False

def reset_login_attempts(username):
    """Reset login attempts after successful login"""
    if username in login_attempts:
        login_attempts[username] = {'count': 0, 'locked_until': None}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Permission required decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not rbac.check_permission(session['username'], permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    """Main landing page"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate username input to prevent injection attacks
        try:
            username = validator.validate_username(username)
        except ValidationError as e:
            logger.log_security_event(
                'INVALID_INPUT',
                f'Invalid username format in login attempt',
                'WARNING',
                username,
                {'error': str(e), 'ip': get_remote_address()}
            )
            flash('Invalid username format', 'danger')
            return render_template('login.html')
        
        # Check if account is locked
        if is_account_locked(username):
            lockout_time = login_attempts[username]['locked_until']
            remaining = (lockout_time - datetime.now()).seconds // 60
            logger.log_security_event(
                'LOGIN_ATTEMPT_LOCKED',
                f'Login attempt for locked account',
                'WARNING',
                username,
                {'remaining_minutes': remaining}
            )
            flash(f'Account locked due to multiple failed attempts. Try again in {remaining} minutes.', 'danger')
            return render_template('login.html')
        
        user = rbac.authenticate(username, password)
        if user:
            reset_login_attempts(username)
            session['username'] = username
            session['role'] = user.role.value
            session['login_time'] = datetime.now().isoformat()
            logger.log_access_control(username, user.role.value, 'login', 'login', True)
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            is_locked = record_failed_login(username)
            attempts_left = MAX_LOGIN_ATTEMPTS - login_attempts[username]['count']
            
            logger.log_access_control(username, 'unknown', 'login', 'login', False, 'Invalid credentials')
            
            if is_locked:
                flash(f'Account locked due to {MAX_LOGIN_ATTEMPTS} failed attempts. Try again in {LOCKOUT_DURATION.seconds // 60} minutes.', 'danger')
            elif attempts_left > 0:
                flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'danger')
            else:
                flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    username = session.get('username')
    if username:
        logger.log_access_control(username, session.get('role'), 'logout', 'logout', True)
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    user = rbac.get_user(session['username'])
    return render_template('dashboard.html', user=user, role=session['role'])

@app.route('/api/upload', methods=['POST'])
@login_required
@permission_required(Permission.READ_DATA)
@limiter.limit("10 per minute")  # Prevent DOS via upload spam
def upload_file():
    """Handle file upload"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate filename for injection attacks
        try:
            validated_filename = validator.validate_string_input(
                file.filename, 
                'Filename', 
                max_length=255, 
                allow_special=False
            )
        except ValidationError as e:
            logger.log_security_event(
                'MALICIOUS_FILENAME',
                f'Potentially malicious filename detected',
                'WARNING',
                session['username'],
                {'filename': file.filename, 'error': str(e)}
            )
            return jsonify({'error': 'Invalid filename'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'Only CSV files are allowed'}), 400
        
        # Secure filename and save
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        
        # Validate and preview
        df = pd.read_csv(filepath)
        
        logger.log_data_access(filepath, 'UPLOAD', session['username'], len(df))
        
        return jsonify({
            'success': True,
            'filename': filename,
            'records': len(df),
            'columns': list(df.columns),
            'preview': df.head(10).to_dict('records')
        })
    
    except Exception as e:
        logger.log_error('UPLOAD_ERROR', str(e), None, session['username'])
        return jsonify({'error': str(e)}), 500

@app.route('/api/anonymize', methods=['POST'])
@login_required
@permission_required(Permission.ANONYMIZE_DATA)
@limiter.limit("20 per hour")  # Rate limit expensive anonymization operations
def anonymize_data():
    """Process anonymization request"""
    try:
        # Validate JSON input
        try:
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Empty JSON data'}), 400
                
        except Exception as e:
            logger.log_security_event(
                'INVALID_JSON',
                f'Invalid JSON in anonymization request',
                'WARNING',
                session['username'],
                {'error': str(e)}
            )
            return jsonify({'error': 'Invalid JSON format'}), 400
        
        input_filename = data.get('filename')
        profile_config = data.get('profile')
        
        if not input_filename or not profile_config:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Load input file
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        if not os.path.exists(input_path):
            return jsonify({'error': 'Input file not found'}), 404
        
        df = pd.read_csv(input_path)
        original_df = df.copy()
        
        # Apply transformations
        key_bytes = profile_config.get('hmac_key', '').encode('utf-8') if profile_config.get('hmac_key') else None
        
        for col, spec in profile_config.get('columns', {}).items():
            if col not in df.columns:
                continue
            
            transform = spec.get('transform')
            params = spec.get('params', {})
            
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
                salt = params.get('salt', profile_config.get('salt', ''))
                df[col] = df[col].apply(lambda v: transforms.salted_hash(v, salt))
            elif transform == 'hmac':
                if not key_bytes:
                    return jsonify({'error': 'HMAC transform requires hmac_key'}), 400
                out_len = params.get('out_len', 12)
                df[col] = df[col].apply(lambda v: transforms.hmac_pseudonymize(v, key_bytes, out_len=out_len))
            elif transform == 'generalize_age':
                bins = params.get('bins')
                df[col] = df[col].apply(lambda v: transforms.generalize_age(v, bins=bins))
            elif transform == 'generalize_numeric':
                precision = params.get('precision', 0)
                df[col] = df[col].apply(lambda v: transforms.generalize_numeric(v, precision))
            
            logger.log_transformation(transform, col, params, len(df), session['username'])
        
        # Apply k-anonymity and l-diversity if configured
        anon_report = None
        if profile_config.get('apply_k_anonymity'):
            quasi_ids = profile_config.get('quasi_identifiers', [])
            sensitive_attr = profile_config.get('sensitive_attribute')
            k = profile_config.get('k', 3)
            l = profile_config.get('l', 2)
            
            if quasi_ids and sensitive_attr:
                df, anon_report = apply_k_anonymity_and_l_diversity(df, quasi_ids, sensitive_attr, k, l)
        
        # Apply differential privacy if configured
        if profile_config.get('apply_differential_privacy'):
            dp_cols = profile_config.get('dp_columns', [])
            epsilon = profile_config.get('epsilon', 1.0)
            delta = profile_config.get('delta', 1e-5)
            
            if dp_cols:
                dp = DifferentialPrivacy(epsilon=epsilon, delta=delta)
                df = dp.apply_to_dataframe(df, dp_cols)
        
        # Save output
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"anonymized_{timestamp}.csv"
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        df.to_csv(output_path, index=False)
        
        logger.log_anonymization(
            'WEB_INTERFACE',
            input_path,
            output_path,
            len(original_df),
            len(df),
            (len(original_df) - len(df)) / len(original_df) * 100 if len(original_df) > 0 else 0,
            profile_config,
            session['username']
        )
        
        # Generate metrics report
        quasi_ids = profile_config.get('quasi_identifiers', [])
        sensitive = profile_config.get('sensitive_attribute')
        numeric = profile_config.get('dp_columns', [])
        
        report = ComprehensiveReport.generate_full_report(
            original_df, df, quasi_ids, sensitive, numeric
        )
        
        return jsonify({
            'success': True,
            'output_filename': output_filename,
            'original_records': len(original_df),
            'anonymized_records': len(df),
            'suppressed_records': len(original_df) - len(df),
            'preview': df.head(10).to_dict('records'),
            'report': report
        })
    
    except Exception as e:
        logger.log_error('ANONYMIZATION_ERROR', str(e), None, session['username'], traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>')
@login_required
@permission_required(Permission.EXPORT_DATA)
def download_file(filename):
    """Download anonymized file"""
    try:
        # Validate filename to prevent path traversal
        try:
            filename = validator.validate_string_input(filename, 'Filename', max_length=255)
        except ValidationError as e:
            logger.log_security_event(
                'PATH_TRAVERSAL_ATTEMPT',
                f'Potentially malicious filename in download request',
                'WARNING',
                session['username'],
                {'filename': filename, 'error': str(e)}
            )
            return jsonify({'error': 'Invalid filename'}), 400
        
        filepath = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(filename))
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        logger.log_data_export(filepath, 0, 'CSV', session['username'])
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit-logs')
@login_required
@permission_required(Permission.VIEW_AUDIT_LOGS)
@limiter.limit("30 per minute")  # Prevent DOS via log requests
def get_audit_logs():
    """Retrieve audit logs"""
    try:
        lines = int(request.args.get('lines', 100))
        logs = logger.get_audit_trail(lines)
        
        # Parse JSON logs
        parsed_logs = []
        for log in logs:
            try:
                parsed_logs.append(json.loads(log))
            except:
                continue
        
        return jsonify({
            'success': True,
            'logs': parsed_logs
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users')
@login_required
@permission_required(Permission.MANAGE_USERS)
def get_users():
    """Get all users (admin only)"""
    try:
        users = rbac.list_users()
        users_data = [
            {
                'username': u.username,
                'role': u.role.value,
                'active': u.active
            }
            for u in users
        ]
        
        return jsonify({
            'success': True,
            'users': users_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MANAGE_USERS)
def register():
    """Admin-only user registration page"""
    if session.get('role') != 'admin':
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'viewer')
        try:
            username = validator.validate_username(username)
            if len(password) < 8:
                raise ValidationError('Password must be at least 8 characters.')
            if role not in ['admin', 'data_owner', 'data_analyst', 'viewer']:
                raise ValidationError('Invalid role.')
            if rbac.get_user(username):
                raise ValidationError('Username already exists.')
            rbac.add_user(username, role=rbac.Role(role), password=password)
            flash(f'User {username} registered successfully.', 'success')
            return redirect(url_for('register'))
        except ValidationError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash('Registration failed: ' + str(e), 'danger')
    return render_template('register.html')

@app.route('/audit-logs')
@login_required
@permission_required(Permission.VIEW_AUDIT_LOGS)
def audit_logs_page():
    """Audit logs viewer page"""
    return render_template('audit_logs.html')

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    logger.log_security_event(
        'RATE_LIMIT_EXCEEDED',
        f'Rate limit exceeded: {e.description}',
        'WARNING',
        session.get('username'),
        {'endpoint': request.endpoint, 'ip': get_remote_address()}
    )
    
    # Return JSON for API requests, HTML for page requests
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Rate limit exceeded. Please slow down your requests.',
            'retry_after': e.description
        }), 429
    else:
        return render_template('429.html'), 429

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
