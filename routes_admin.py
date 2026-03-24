"""
Admin panel routes for managing candidates, voters, and elections.
"""
import os
import secrets
import datetime
import json
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from extensions import db
from models import User, Candidate, Election, Vote, AuditLog, FraudAlert
from routes_auth import admin_required
from fraud_detection import FraudDetector

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ============ CANDIDATE MANAGEMENT ============

@admin_bp.route('/candidates', methods=['GET'])
@admin_required
def get_candidates(current_user):
    """Get all candidates, optionally filtered by election."""
    election_id = request.args.get('election_id', type=int)
    
    query = Candidate.query
    if election_id:
        query = query.filter_by(election_id=election_id)
    
    candidates = query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'party': c.party,
        'bio': c.bio,
        'image_path': c.image_path,
        'election_id': c.election_id,
        'vote_count': c.vote_count,
        'created_at': str(c.created_at)
    } for c in candidates])


@admin_bp.route('/candidates', methods=['POST'])
@admin_required
def create_candidate(current_user):
    """Add a new candidate."""
    data = request.form if request.form else request.get_json() or {}
    
    name = data.get('name', '').strip()
    party = data.get('party', '').strip()
    bio = data.get('bio', '').strip()
    election_id = data.get('election_id', type=int) if request.form else data.get('election_id')
    
    if not name:
        return jsonify({'error': 'Candidate name is required'}), 400
    if not election_id:
        return jsonify({'error': 'Election ID is required'}), 400
    
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    # Handle image upload
    image_path = None
    if 'image' in request.files:
        img_file = request.files['image']
        if img_file and allowed_file(img_file.filename):
            filename = secure_filename(f"candidate_{secrets.token_hex(8)}_{img_file.filename}")
            filepath = os.path.join(current_app.config['CANDIDATE_FOLDER'], filename)
            img_file.save(filepath)
            image_path = f"/uploads/candidates/{filename}"
    
    candidate = Candidate(
        name=name,
        party=party,
        bio=bio,
        image_path=image_path,
        election_id=election_id
    )
    
    db.session.add(candidate)
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='candidate_created',
                    details=f'Created candidate: {name}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Candidate created successfully',
        'candidate': {
            'id': candidate.id,
            'name': candidate.name,
            'party': candidate.party,
            'bio': candidate.bio,
            'image_path': candidate.image_path,
            'election_id': candidate.election_id
        }
    }), 201


@admin_bp.route('/candidates/<int:candidate_id>', methods=['PUT'])
@admin_required
def update_candidate(current_user, candidate_id):
    """Update an existing candidate."""
    candidate = Candidate.query.get(candidate_id)
    if not candidate:
        return jsonify({'error': 'Candidate not found'}), 404
    
    data = request.form if request.form else request.get_json() or {}
    
    if 'name' in data:
        candidate.name = data['name'].strip()
    if 'party' in data:
        candidate.party = data['party'].strip()
    if 'bio' in data:
        candidate.bio = data['bio'].strip()
    
    # Handle image update
    if 'image' in request.files:
        img_file = request.files['image']
        if img_file and allowed_file(img_file.filename):
            # Delete old image
            if candidate.image_path:
                old_path = os.path.join(current_app.root_path, candidate.image_path.lstrip('/'))
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            filename = secure_filename(f"candidate_{secrets.token_hex(8)}_{img_file.filename}")
            filepath = os.path.join(current_app.config['CANDIDATE_FOLDER'], filename)
            img_file.save(filepath)
            candidate.image_path = f"/uploads/candidates/{filename}"
    
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='candidate_updated',
                    details=f'Updated candidate: {candidate.name}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Candidate updated successfully'})


@admin_bp.route('/candidates/<int:candidate_id>', methods=['DELETE'])
@admin_required
def delete_candidate(current_user, candidate_id):
    """Delete a candidate."""
    candidate = Candidate.query.get(candidate_id)
    if not candidate:
        return jsonify({'error': 'Candidate not found'}), 404
    
    # Don't allow deleting if election is ongoing
    if candidate.election.is_ongoing():
        return jsonify({'error': 'Cannot delete candidate during ongoing election'}), 400
    
    name = candidate.name
    
    # Delete image
    if candidate.image_path:
        full_path = os.path.join(current_app.root_path, candidate.image_path.lstrip('/'))
        if os.path.exists(full_path):
            os.remove(full_path)
    
    db.session.delete(candidate)
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='candidate_deleted',
                    details=f'Deleted candidate: {name}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Candidate deleted successfully'})


# ============ VOTER MANAGEMENT ============

@admin_bp.route('/voters', methods=['GET'])
@admin_required
def get_voters(current_user):
    """Get all registered voters."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '').strip()
    
    query = User.query.filter_by(role='voter')
    
    if search:
        query = query.filter(
            (User.username.contains(search)) |
            (User.full_name.contains(search)) |
            (User.email.contains(search)) |
            (User.national_id.contains(search))
        )
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    voters = pagination.items
    
    return jsonify({
        'voters': [{
            'id': v.id,
            'username': v.username,
            'email': v.email,
            'full_name': v.full_name,
            'phone': v.phone,
            'national_id': v.national_id,
            'is_verified': v.is_verified,
            'is_active': v.is_active_user,
            'has_fingerprint': v.fingerprint_hash is not None,
            'has_voted': v.has_voted,
            'created_at': str(v.created_at)
        } for v in voters],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@admin_bp.route('/voters/<int:voter_id>/verify', methods=['POST'])
@admin_required
def verify_voter(current_user, voter_id):
    """Verify a voter's identity."""
    voter = User.query.get(voter_id)
    if not voter:
        return jsonify({'error': 'Voter not found'}), 404
    if voter.role != 'voter':
        return jsonify({'error': 'User is not a voter'}), 400
    
    voter.is_verified = True
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='voter_verified',
                    details=f'Verified voter: {voter.full_name} (ID: {voter.national_id})',
                    ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': f'Voter {voter.full_name} verified successfully'})


@admin_bp.route('/voters/<int:voter_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_voter_status(current_user, voter_id):
    """Activate or deactivate a voter."""
    voter = User.query.get(voter_id)
    if not voter:
        return jsonify({'error': 'Voter not found'}), 404
    
    voter.is_active_user = not voter.is_active_user
    db.session.commit()
    
    status = 'activated' if voter.is_active_user else 'deactivated'
    audit = AuditLog(user_id=current_user.id, action=f'voter_{status}',
                    details=f'{status.capitalize()} voter: {voter.full_name}',
                    ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': f'Voter {status} successfully', 'is_active': voter.is_active_user})


# ============ ELECTION MANAGEMENT ============

@admin_bp.route('/elections', methods=['GET'])
@admin_required
def get_elections(current_user):
    """Get all elections."""
    elections = Election.query.order_by(Election.created_at.desc()).all()
    return jsonify([{
        'id': e.id,
        'title': e.title,
        'description': e.description,
        'start_date': str(e.start_date),
        'end_date': str(e.end_date),
        'is_active': e.is_active,
        'is_ongoing': e.is_ongoing(),
        'total_voters': e.total_voters,
        'total_votes': Vote.query.filter_by(election_id=e.id).count(),
        'candidate_count': Candidate.query.filter_by(election_id=e.id).count(),
        'created_at': str(e.created_at)
    } for e in elections])


@admin_bp.route('/elections', methods=['POST'])
@admin_required
def create_election(current_user):
    """Create a new election."""
    data = request.get_json() or {}
    
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    
    if not title:
        return jsonify({'error': 'Election title is required'}), 400
    if not start_date or not end_date:
        return jsonify({'error': 'Start and end dates are required'}), 400
    
    try:
        start_dt = datetime.datetime.fromisoformat(start_date.replace('Z', '+00:00').replace('+00:00', ''))
        end_dt = datetime.datetime.fromisoformat(end_date.replace('Z', '+00:00').replace('+00:00', ''))
    except (ValueError, AttributeError):
        return jsonify({'error': 'Invalid date format. Use ISO format.'}), 400
    
    if end_dt <= start_dt:
        return jsonify({'error': 'End date must be after start date'}), 400
    
    total_voters = User.query.filter_by(role='voter', is_verified=True, is_active_user=True).count()
    
    election = Election(
        title=title,
        description=description,
        start_date=start_dt,
        end_date=end_dt,
        is_active=True,
        created_by=current_user.id,
        total_voters=total_voters
    )
    
    db.session.add(election)
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='election_created',
                    details=f'Created election: {title}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Election created successfully',
        'election': {
            'id': election.id,
            'title': election.title,
            'start_date': str(election.start_date),
            'end_date': str(election.end_date)
        }
    }), 201


@admin_bp.route('/elections/<int:election_id>', methods=['PUT'])
@admin_required
def update_election(current_user, election_id):
    """Update election details."""
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    data = request.get_json() or {}
    
    if 'title' in data:
        election.title = data['title'].strip()
    if 'description' in data:
        election.description = data['description'].strip()
    if 'start_date' in data:
        try:
            election.start_date = datetime.datetime.fromisoformat(data['start_date'].replace('Z', '+00:00').replace('+00:00', ''))
        except (ValueError, AttributeError):
            return jsonify({'error': 'Invalid start date format'}), 400
    if 'end_date' in data:
        try:
            election.end_date = datetime.datetime.fromisoformat(data['end_date'].replace('Z', '+00:00').replace('+00:00', ''))
        except (ValueError, AttributeError):
            return jsonify({'error': 'Invalid end date format'}), 400
    if 'is_active' in data:
        election.is_active = bool(data['is_active'])
    
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='election_updated',
                    details=f'Updated election: {election.title}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Election updated successfully'})


@admin_bp.route('/elections/<int:election_id>', methods=['DELETE'])
@admin_required
def delete_election(current_user, election_id):
    """Delete an election (only if no votes cast)."""
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    vote_count = Vote.query.filter_by(election_id=election_id).count()
    if vote_count > 0:
        return jsonify({'error': 'Cannot delete election with existing votes'}), 400
    
    # Delete associated candidates
    Candidate.query.filter_by(election_id=election_id).delete()
    
    title = election.title
    db.session.delete(election)
    db.session.commit()
    
    audit = AuditLog(user_id=current_user.id, action='election_deleted',
                    details=f'Deleted election: {title}', ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({'message': 'Election deleted successfully'})


# ============ FRAUD & ANALYTICS ============

@admin_bp.route('/fraud-analysis/<int:election_id>', methods=['GET'])
@admin_required
def fraud_analysis(current_user, election_id):
    """Run fraud analysis on an election."""
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    report = FraudDetector.run_full_analysis(election_id)
    return jsonify(report)


@admin_bp.route('/fraud-alerts', methods=['GET'])
@admin_required
def get_fraud_alerts(current_user):
    """Get all fraud alerts."""
    election_id = request.args.get('election_id', type=int)
    
    query = FraudAlert.query
    if election_id:
        query = query.filter_by(election_id=election_id)
    
    alerts = query.order_by(FraudAlert.timestamp.desc()).all()
    return jsonify([{
        'id': a.id,
        'election_id': a.election_id,
        'alert_type': a.alert_type,
        'severity': a.severity,
        'description': a.description,
        'is_resolved': a.is_resolved,
        'timestamp': str(a.timestamp)
    } for a in alerts])


@admin_bp.route('/audit-logs', methods=['GET'])
@admin_required
def get_audit_logs(current_user):
    """Get audit logs."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    pagination = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    logs = pagination.items
    return jsonify({
        'logs': [{
            'id': l.id,
            'user_id': l.user_id,
            'action': l.action,
            'details': l.details,
            'ip_address': l.ip_address,
            'timestamp': str(l.timestamp)
        } for l in logs],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def admin_stats(current_user):
    """Get admin dashboard statistics."""
    total_voters = User.query.filter_by(role='voter').count()
    verified_voters = User.query.filter_by(role='voter', is_verified=True).count()
    active_elections = Election.query.filter_by(is_active=True).count()
    total_votes = Vote.query.count()
    total_candidates = Candidate.query.count()
    fraud_alerts = FraudAlert.query.filter_by(is_resolved=False).count()
    
    return jsonify({
        'total_voters': total_voters,
        'verified_voters': verified_voters,
        'unverified_voters': total_voters - verified_voters,
        'active_elections': active_elections,
        'total_elections': Election.query.count(),
        'total_votes': total_votes,
        'total_candidates': total_candidates,
        'pending_fraud_alerts': fraud_alerts
    })
