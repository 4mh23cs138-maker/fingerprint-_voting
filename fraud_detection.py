"""
Fraud detection system for identifying suspicious voting patterns.
Uses statistical analysis and rule-based detection.
"""
import datetime
import json
from collections import Counter, defaultdict
from models import Vote, User, Election, FraudAlert, AuditLog
from extensions import db


class FraudDetector:
    """AI-powered fraud detection for voting systems."""
    
    # Thresholds
    RAPID_VOTE_THRESHOLD_SECONDS = 5  # Minimum seconds between operations
    BULK_VOTE_THRESHOLD = 10  # Max votes from single IP in short time
    BULK_VOTE_WINDOW_MINUTES = 10
    ANOMALY_RATIO_THRESHOLD = 0.8  # If one candidate gets > 80% from one IP
    
    @staticmethod
    def check_rapid_voting(user_id, election_id):
        """
        Check if the user is voting too quickly (potential bot).
        """
        recent_logs = AuditLog.query.filter_by(
            user_id=user_id,
            action='vote_attempt'
        ).order_by(AuditLog.timestamp.desc()).limit(5).all()
        
        if len(recent_logs) >= 2:
            time_diff = (recent_logs[0].timestamp - recent_logs[1].timestamp).total_seconds()
            if time_diff < FraudDetector.RAPID_VOTE_THRESHOLD_SECONDS:
                return True, f"Rapid voting detected: {time_diff:.1f}s between attempts"
        
        return False, None
    
    @staticmethod
    def check_ip_anomaly(ip_address, election_id):
        """
        Check if too many votes are coming from the same IP address.
        """
        window_start = datetime.datetime.utcnow() - datetime.timedelta(
            minutes=FraudDetector.BULK_VOTE_WINDOW_MINUTES
        )
        
        recent_votes = Vote.query.filter(
            Vote.election_id == election_id,
            Vote.ip_address == ip_address,
            Vote.timestamp >= window_start
        ).count()
        
        if recent_votes >= FraudDetector.BULK_VOTE_THRESHOLD:
            return True, f"Bulk voting from IP {ip_address}: {recent_votes} votes in {FraudDetector.BULK_VOTE_WINDOW_MINUTES} minutes"
        
        return False, None
    
    @staticmethod
    def check_voting_pattern_anomaly(election_id):
        """
        Analyze voting patterns for statistical anomalies.
        Checks for unusual distribution of votes from specific sources.
        """
        alerts = []
        
        # Get all votes for this election
        votes = Vote.query.filter_by(election_id=election_id).all()
        
        if len(votes) < 10:
            return alerts  # Not enough data
        
        # Group votes by IP address
        ip_votes = defaultdict(list)
        for vote in votes:
            ip_votes[vote.ip_address].append(vote.candidate_id)
        
        # Check if any IP is voting heavily for one candidate
        for ip, candidate_ids in ip_votes.items():
            if len(candidate_ids) < 3:
                continue
            
            counter = Counter(candidate_ids)
            most_common_count = counter.most_common(1)[0][1]
            ratio = most_common_count / len(candidate_ids)
            
            if ratio >= FraudDetector.ANOMALY_RATIO_THRESHOLD:
                alerts.append({
                    'type': 'ip_bias',
                    'severity': 'high',
                    'description': f"IP {ip} shows {ratio*100:.0f}% bias toward candidate {counter.most_common(1)[0][0]}"
                })
        
        # Check for time-based anomalies (voting bursts)
        if len(votes) >= 5:
            timestamps = sorted([v.timestamp for v in votes])
            for i in range(len(timestamps) - 4):
                window = (timestamps[i + 4] - timestamps[i]).total_seconds()
                if window < 30:  # 5 votes in 30 seconds
                    alerts.append({
                        'type': 'vote_burst',
                        'severity': 'medium',
                        'description': f"Voting burst detected: 5 votes in {window:.1f}s around {timestamps[i]}"
                    })
        
        return alerts
    
    @staticmethod
    def run_full_analysis(election_id):
        """
        Run complete fraud analysis on an election.
        Returns a report with findings and risk level.
        """
        alerts = []
        
        # Pattern analysis
        pattern_alerts = FraudDetector.check_voting_pattern_anomaly(election_id)
        alerts.extend(pattern_alerts)
        
        # Check for duplicate fingerprint hashes
        votes = Vote.query.filter_by(election_id=election_id).all()
        user_ids = [v.user_id for v in votes]
        
        users = User.query.filter(User.id.in_(user_ids)).all()
        fingerprint_hashes = [u.fingerprint_hash for u in users if u.fingerprint_hash]
        
        hash_counter = Counter(fingerprint_hashes)
        for fp_hash, count in hash_counter.items():
            if count > 1:
                alerts.append({
                    'type': 'duplicate_biometric',
                    'severity': 'critical',
                    'description': f"Duplicate fingerprint hash detected: {count} users share the same biometric"
                })
        
        # Store alerts in database
        for alert_data in alerts:
            existing = FraudAlert.query.filter_by(
                election_id=election_id,
                alert_type=alert_data['type'],
                description=alert_data['description']
            ).first()
            
            if not existing:
                alert = FraudAlert(
                    election_id=election_id,
                    alert_type=alert_data['type'],
                    severity=alert_data['severity'],
                    description=alert_data['description']
                )
                db.session.add(alert)
        
        db.session.commit()
        
        # Calculate overall risk level
        severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if not alerts:
            risk_level = 'low'
            risk_score = 0
        else:
            max_severity = max(severity_scores.get(a['severity'], 0) for a in alerts)
            risk_score = max_severity
            risk_level = {0: 'low', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}.get(max_severity, 'low')
        
        return {
            'election_id': election_id,
            'total_votes': len(votes),
            'alerts': alerts,
            'alert_count': len(alerts),
            'risk_level': risk_level,
            'risk_score': risk_score,
            'analysis_timestamp': str(datetime.datetime.utcnow())
        }
    
    @staticmethod
    def validate_vote(user_id, election_id, ip_address):
        """
        Pre-vote validation. Returns (is_valid, reasons).
        """
        issues = []
        
        # Check rapid voting
        is_rapid, rapid_msg = FraudDetector.check_rapid_voting(user_id, election_id)
        if is_rapid:
            issues.append(rapid_msg)
        
        # Check IP anomaly
        is_ip_anomaly, ip_msg = FraudDetector.check_ip_anomaly(ip_address, election_id)
        if is_ip_anomaly:
            issues.append(ip_msg)
        
        # Check if user already voted
        existing_vote = Vote.query.filter_by(
            user_id=user_id,
            election_id=election_id
        ).first()
        if existing_vote:
            issues.append("User has already voted in this election")
        
        is_valid = len(issues) == 0
        return is_valid, issues
