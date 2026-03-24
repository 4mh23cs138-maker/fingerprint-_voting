"""
Voting routes - handles the actual voting process.
"""
import json
import datetime
from flask import Blueprint, request, jsonify
from extensions import db
from models import User, Candidate, Election, Vote, AuditLog
from routes_auth import token_required
from blockchain import Blockchain
from fraud_detection import FraudDetector

vote_bp = Blueprint('vote', __name__, url_prefix='/api/vote')


@vote_bp.route('/elections', methods=['GET'])
@token_required
def get_active_elections(current_user):
    """Get all active/ongoing elections for voters."""
    now = datetime.datetime.utcnow()
    elections = Election.query.filter(
        Election.is_active == True,
        Election.start_date <= now,
        Election.end_date >= now
    ).all()
    
    result = []
    for e in elections:
        voted_elections = current_user.get_voted_elections()
        has_voted = e.id in voted_elections
        
        result.append({
            'id': e.id,
            'title': e.title,
            'description': e.description,
            'start_date': str(e.start_date),
            'end_date': str(e.end_date),
            'has_voted': has_voted,
            'candidates': [{
                'id': c.id,
                'name': c.name,
                'party': c.party,
                'bio': c.bio,
                'image_path': c.image_path
            } for c in e.candidates]
        })
    
    return jsonify(result)


@vote_bp.route('/all-elections', methods=['GET'])
@token_required
def get_all_elections(current_user):
    """Get all elections (active, past, and future)."""
    elections = Election.query.order_by(Election.start_date.desc()).all()
    
    result = []
    for e in elections:
        voted_elections = current_user.get_voted_elections()
        has_voted = e.id in voted_elections
        total_votes = Vote.query.filter_by(election_id=e.id).count()
        
        now = datetime.datetime.utcnow()
        if now < e.start_date:
            status = 'upcoming'
        elif now > e.end_date:
            status = 'ended'
        elif e.is_active:
            status = 'ongoing'
        else:
            status = 'paused'
        
        result.append({
            'id': e.id,
            'title': e.title,
            'description': e.description,
            'start_date': str(e.start_date),
            'end_date': str(e.end_date),
            'status': status,
            'has_voted': has_voted,
            'total_votes': total_votes,
            'candidate_count': len(e.candidates)
        })
    
    return jsonify(result)


@vote_bp.route('/cast', methods=['POST'])
@token_required
def cast_vote(current_user):
    """Cast a vote for a candidate."""
    data = request.get_json() or {}
    
    candidate_id = data.get('candidate_id')
    election_id = data.get('election_id')
    
    if not candidate_id or not election_id:
        return jsonify({'error': 'Candidate ID and Election ID are required'}), 400
    
    # Check if voter is verified
    if not current_user.is_verified:
        return jsonify({'error': 'Your identity has not been verified yet. Please contact admin.'}), 403
    
    # Check election
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    if not election.is_ongoing():
        return jsonify({'error': 'This election is not currently active'}), 400
    
    # Check candidate
    candidate = Candidate.query.get(candidate_id)
    if not candidate:
        return jsonify({'error': 'Candidate not found'}), 404
    if candidate.election_id != election_id:
        return jsonify({'error': 'Candidate does not belong to this election'}), 400
    
    # Log vote attempt for fraud detection
    audit = AuditLog(user_id=current_user.id, action='vote_attempt',
                    details=json.dumps({'election_id': election_id, 'candidate_id': candidate_id}),
                    ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    # Fraud detection
    is_valid, issues = FraudDetector.validate_vote(
        current_user.id, election_id, request.remote_addr
    )
    
    if not is_valid:
        # Mark suspicious
        for issue in issues:
            audit = AuditLog(user_id=current_user.id, action='vote_blocked',
                           details=issue, ip_address=request.remote_addr)
            db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            'error': 'Vote cannot be processed',
            'reasons': issues
        }), 403
    
    # Check double voting (database level)
    existing_vote = Vote.query.filter_by(
        user_id=current_user.id,
        election_id=election_id
    ).first()
    
    if existing_vote:
        return jsonify({'error': 'You have already voted in this election'}), 409
    
    # Record vote on blockchain
    try:
        block = Blockchain.add_vote_block(current_user.id, candidate_id, election_id)
        block_hash = block.hash
    except Exception as e:
        block_hash = None
    
    # Cast vote
    vote = Vote(
        user_id=current_user.id,
        candidate_id=candidate_id,
        election_id=election_id,
        block_hash=block_hash,
        ip_address=request.remote_addr,
        is_suspicious=False
    )
    
    db.session.add(vote)
    
    # Update candidate vote count
    candidate.vote_count += 1
    
    # Update user voting status
    current_user.has_voted = True
    current_user.add_voted_election(election_id)
    
    db.session.commit()
    
    # Audit log
    audit = AuditLog(user_id=current_user.id, action='vote_cast',
                    details=json.dumps({
                        'election_id': election_id,
                        'block_hash': block_hash[:16] + '...' if block_hash else None
                    }),
                    ip_address=request.remote_addr)
    db.session.add(audit)
    db.session.commit()
    
    return jsonify({
        'message': 'Vote cast successfully!',
        'block_hash': block_hash,
        'timestamp': str(vote.timestamp)
    })


@vote_bp.route('/results/<int:election_id>', methods=['GET'])
@token_required
def get_results(current_user, election_id):
    """Get election results."""
    election = Election.query.get(election_id)
    if not election:
        return jsonify({'error': 'Election not found'}), 404
    
    candidates = Candidate.query.filter_by(election_id=election_id).all()
    total_votes = sum(c.vote_count for c in candidates)
    
    results = []
    for c in candidates:
        percentage = (c.vote_count / total_votes * 100) if total_votes > 0 else 0
        results.append({
            'id': c.id,
            'name': c.name,
            'party': c.party,
            'image_path': c.image_path,
            'votes': c.vote_count,
            'percentage': round(percentage, 2)
        })
    
    # Sort by votes descending
    results.sort(key=lambda x: x['votes'], reverse=True)
    
    return jsonify({
        'election': {
            'id': election.id,
            'title': election.title,
            'start_date': str(election.start_date),
            'end_date': str(election.end_date),
            'is_ongoing': election.is_ongoing(),
            'total_voters': election.total_voters,
            'total_votes': total_votes,
            'turnout': round(float(total_votes / election.total_voters * 100), 2) if election.total_voters > 0 else 0
        },
        'results': results
    })


@vote_bp.route('/blockchain/verify', methods=['GET'])
@token_required
def verify_blockchain(current_user):
    """Verify blockchain integrity."""
    is_valid, message = Blockchain.verify_chain()
    chain_data = Blockchain.get_chain_data()
    
    return jsonify({
        'is_valid': is_valid,
        'message': message,
        'chain_length': len(chain_data),
        'chain': chain_data[-10:]  # Last 10 blocks
    })


@vote_bp.route('/dashboard-stats', methods=['GET'])
@token_required
def dashboard_stats(current_user):
    """Get statistics for voter dashboard."""
    now = datetime.datetime.utcnow()
    
    # Active elections
    active_elections = Election.query.filter(
        Election.is_active == True,
        Election.start_date <= now,
        Election.end_date >= now
    ).count()
    
    # User's voting history
    voted_elections = current_user.get_voted_elections()
    
    # Total elections
    total_elections = Election.query.count()
    
    # Recent votes by the user
    recent_votes = Vote.query.filter_by(user_id=current_user.id).order_by(
        Vote.timestamp.desc()
    ).limit(5).all()
    
    return jsonify({
        'active_elections': active_elections,
        'total_elections': total_elections,
        'elections_voted': len(voted_elections),
        'is_verified': current_user.is_verified,
        'has_fingerprint': current_user.fingerprint_hash is not None,
        'recent_votes': [{
            'election_id': v.election_id,
            'timestamp': str(v.timestamp),
            'block_hash': v.block_hash[:16] + '...' if v.block_hash else None
        } for v in recent_votes]
    })
