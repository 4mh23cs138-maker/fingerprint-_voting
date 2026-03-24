import datetime
import hashlib
import json
from flask_login import UserMixin
from extensions import db


class User(UserMixin, db.Model):
    """User model for voters and administrators."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    national_id = db.Column(db.String(50), unique=True)
    role = db.Column(db.String(20), default='voter')  # 'admin' or 'voter'
    is_verified = db.Column(db.Boolean, default=False)
    is_active_user = db.Column(db.Boolean, default=True)
    fingerprint_hash = db.Column(db.String(256))
    fingerprint_template = db.Column(db.LargeBinary)  # Stored encrypted
    otp_secret = db.Column(db.String(32))
    has_voted = db.Column(db.Boolean, default=False)
    voted_election_ids = db.Column(db.Text, default='[]')  # JSON list of election IDs
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def get_voted_elections(self):
        try:
            return json.loads(self.voted_election_ids or '[]')
        except json.JSONDecodeError:
            return []
    
    def add_voted_election(self, election_id):
        elections = self.get_voted_elections()
        if election_id not in elections:
            elections.append(election_id)
            self.voted_election_ids = json.dumps(elections)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Candidate(db.Model):
    """Candidate model for elections."""
    __tablename__ = 'candidates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    party = db.Column(db.String(100))
    bio = db.Column(db.Text)
    image_path = db.Column(db.String(256))
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'), nullable=False)
    vote_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    election = db.relationship('Election', backref=db.backref('candidates', lazy=True))
    
    def __repr__(self):
        return f'<Candidate {self.name}>'


class Election(db.Model):
    """Election model."""
    __tablename__ = 'elections'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    total_voters = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def is_ongoing(self):
        now = datetime.datetime.utcnow()
        return self.is_active and self.start_date <= now <= self.end_date
    
    def __repr__(self):
        return f'<Election {self.title}>'


class Vote(db.Model):
    """Vote record model."""
    __tablename__ = 'votes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    block_hash = db.Column(db.String(256))  # Blockchain reference
    ip_address = db.Column(db.String(45))
    is_suspicious = db.Column(db.Boolean, default=False)
    
    # Unique constraint to prevent double voting
    __table_args__ = (
        db.UniqueConstraint('user_id', 'election_id', name='unique_vote_per_election'),
    )
    
    user = db.relationship('User', backref=db.backref('votes', lazy=True))
    candidate = db.relationship('Candidate', backref=db.backref('votes', lazy=True))
    election = db.relationship('Election', backref=db.backref('votes', lazy=True))
    
    def __repr__(self):
        return f'<Vote user={self.user_id} candidate={self.candidate_id}>'


class BlockchainBlock(db.Model):
    """Blockchain block for vote immutability."""
    __tablename__ = 'blockchain'
    
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    vote_data = db.Column(db.Text, nullable=False)  # JSON encrypted vote data
    previous_hash = db.Column(db.String(256), nullable=False)
    nonce = db.Column(db.Integer, default=0)
    hash = db.Column(db.String(256), nullable=False, unique=True)
    
    def __repr__(self):
        return f'<Block {self.index} hash={self.hash[:16]}...>'


class AuditLog(db.Model):
    """Audit log for tracking system events."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    
    def __repr__(self):
        return f'<AuditLog {self.action}>'


class FraudAlert(db.Model):
    """Fraud detection alerts."""
    __tablename__ = 'fraud_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'))
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    description = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    election = db.relationship('Election', backref=db.backref('fraud_alerts', lazy=True))
    
    def __repr__(self):
        return f'<FraudAlert {self.alert_type} severity={self.severity}>'
