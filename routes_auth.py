"""
Authentication and user management routes.
"""
import os
import json
import secrets
import datetime
import hashlib
import bcrypt
import pyotp
import jwt
from functools import wraps
from flask import Blueprint, request, jsonify, current_app, session
from werkzeug.utils import secure_filename
from extensions import db, limiter
from models import User, AuditLog
from fingerprint_engine import match_fingerprints, generate_fingerprint_hash, generate_template

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_token(user_id, role):
    """Generate JWT token."""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')


def token_required(f):
    """Decorator to protect routes with JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            # Also check session
            token = session.get('token')
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
            if not current_user.is_active_user:
                return jsonify({'error': 'Account deactivated'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to restrict access to admins only."""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    """Register a new voter."""
    data = request.form if request.form else request.get_json() or {}
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    phone = data.get('phone', '').strip()
    national_id = data.get('national_id', '').strip()
    
    # Validation
    errors = []
    if not username or len(username) < 3:
        errors.append('Username must be at least 3 characters')
    if not email or '@' not in email:
        errors.append('Valid email is required')
    if not password or len(password) < 6:
        errors.append('Password must be at least 6 characters')
    if not full_name:
        errors.append('Full name is required')
    if not national_id:
        errors.append('National ID is required')
    
    if errors:
        return jsonify({'error': errors}), 400
    
    # Check duplicates
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
    if User.query.filter_by(national_id=national_id).first():
        return jsonify({'error': 'National ID already registered'}), 409
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Handle fingerprint upload
    fingerprint_hash = None
    fingerprint_template = None
    
    if 'fingerprint' in request.files:
        fp_file = request.files['fingerprint']
        if fp_file and allowed_file(fp_file.filename):
            fp_data = fp_file.read()
            fingerprint_hash = generate_fingerprint_hash(fp_data)
            fingerprint_template = generate_template(fp_data)
            
            # Check for duplicate fingerprint
            existing_fp = User.query.filter_by(fingerprint_hash=fingerprint_hash).first()
            if existing_fp:
                return jsonify({'error': 'This fingerprint is already registered'}), 409
            
            # Save original fingerprint file
            filename = secure_filename(f"{username}_{secrets.token_hex(8)}.png")
            filepath = os.path.join(current_app.config['FINGERPRINT_FOLDER'], filename)
            fp_file.seek(0)
            fp_file.save(filepath)
    
    # Generate OTP secret
    otp_secret = pyotp.random_base32()
    
    # Get role, restrict to valid roles and default to voter
    role = data.get('role', 'voter').strip().lower()
    if role not in ['voter', 'admin']:
        role = 'voter'

    # Create user
    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        phone=phone,
        national_id=national_id,
        role=role,
        fingerprint_hash=fingerprint_hash,
        fingerprint_template=fingerprint_template,
        otp_secret=otp_secret,
        is_verified=False
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Audit log
    audit = AuditLog(user_id=user.id, action='register', details='New voter registration',
                     ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Registration successful. Awaiting admin verification.',
        'user_id': user.id,
        'otp_secret': otp_secret
    }), 201


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("20 per hour")
def login():
    """Login with username/email and password."""
    data = request.get_json() or {}
    
    identifier = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not identifier or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier)
    ).first()
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        # Log failed attempt
        audit = AuditLog(user_id=user.id, action='login_failed',
                        details='Invalid password', ip_address=request.remote_addr)
        db.session.add(audit)
        db.session.commit()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active_user:
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Generate token
    token = generate_token(user.id, user.role)
    
    # Store in session
    session['token'] = token
    session['user_id'] = user.id
    
    # Audit log
    audit = AuditLog(user_id=user.id, action='login', details='Successful login',
                    ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username,
            'full_name': user.full_name,
            'role': user.role,
            'is_verified': user.is_verified,
            'has_fingerprint': user.fingerprint_hash is not None
        }
    })


@auth_bp.route('/verify-otp', methods=['POST'])
@limiter.limit("10 per hour")
def verify_otp():
    """Verify OTP for multi-factor authentication."""
    data = request.get_json() or {}
    user_id = data.get('user_id')
    otp_code = data.get('otp_code', '')
    
    if not user_id or not otp_code:
        return jsonify({'error': 'User ID and OTP code are required'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    totp = pyotp.TOTP(user.otp_secret)
    
    if totp.verify(otp_code, valid_window=2):
        # Audit log
        audit = AuditLog(user_id=user.id, action='otp_verified',
                        details='OTP verification successful', ip_address=request.remote_addr)
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({'message': 'OTP verified successfully', 'verified': True})
    
    return jsonify({'error': 'Invalid OTP code', 'verified': False}), 401


@auth_bp.route('/generate-otp', methods=['POST'])
@token_required
def generate_otp(current_user):
    """Generate a new OTP for the current user."""
    totp = pyotp.TOTP(current_user.otp_secret)
    otp = totp.now()
    
    return jsonify({
        'message': 'OTP generated',
        'otp': otp,  # In production, send via email/SMS instead
        'valid_for': '30 seconds',
        'note': 'In production, this would be sent via email or SMS'
    })


@auth_bp.route('/verify-fingerprint', methods=['POST'])
@token_required
def verify_fingerprint(current_user):
    """Verify fingerprint for authentication."""
    if 'fingerprint' not in request.files:
        return jsonify({'error': 'Fingerprint image is required'}), 400
    
    fp_file = request.files['fingerprint']
    if not fp_file or not allowed_file(fp_file.filename):
        return jsonify({'error': 'Invalid fingerprint image'}), 400
    
    if not current_user.fingerprint_template:
        return jsonify({'error': 'No fingerprint enrolled for this user'}), 400
    
    # Read uploaded fingerprint
    fp_data = fp_file.read()
    
    # Match against stored template
    is_match, score, method = match_fingerprints(fp_data, current_user.fingerprint_template)
    
    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action='fingerprint_verify',
        details=json.dumps({'match': is_match, 'score': score, 'method': method}),
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()
    
    if is_match:
        return jsonify({
            'message': 'Fingerprint verified',
            'match': True,
            'score': score,
            'method': method
        })
    
    return jsonify({
        'error': 'Fingerprint does not match',
        'match': False,
        'score': score,
        'method': method
    }), 401


@auth_bp.route('/enroll-fingerprint', methods=['POST'])
@token_required
def enroll_fingerprint(current_user):
    """Enroll a new fingerprint for the user."""
    if 'fingerprint' not in request.files:
        return jsonify({'error': 'Fingerprint image is required'}), 400
    
    fp_file = request.files['fingerprint']
    if not fp_file or not allowed_file(fp_file.filename):
        return jsonify({'error': 'Invalid fingerprint image format'}), 400
    
    fp_data = fp_file.read()
    
    # Generate hash and template
    fp_hash = generate_fingerprint_hash(fp_data)
    fp_template = generate_template(fp_data)
    
    if not fp_template:
        return jsonify({'error': 'Could not process fingerprint image'}), 400
    
    # Check for duplicate
    existing = User.query.filter(
        User.fingerprint_hash == fp_hash,
        User.id != current_user.id
    ).first()
    if existing:
        return jsonify({'error': 'This fingerprint is already registered to another user'}), 409
    
    # Save fingerprint file
    filename = secure_filename(f"{current_user.username}_{secrets.token_hex(8)}.png")
    filepath = os.path.join(current_app.config['FINGERPRINT_FOLDER'], filename)
    fp_file.seek(0)
    fp_file.save(filepath)
    
    # Update user
    current_user.fingerprint_hash = fp_hash
    current_user.fingerprint_template = fp_template
    db.session.commit()
    
    # Audit log
    audit = AuditLog(user_id=current_user.id, action='fingerprint_enrolled',
                    details='Fingerprint enrolled successfully', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Fingerprint enrolled successfully'})


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user profile."""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'full_name': current_user.full_name,
        'phone': current_user.phone,
        'national_id': current_user.national_id,
        'role': current_user.role,
        'is_verified': current_user.is_verified,
        'has_fingerprint': current_user.fingerprint_hash is not None,
        'created_at': str(current_user.created_at)
    })


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user."""
    session.clear()
    return jsonify({'message': 'Logged out successfully'})
