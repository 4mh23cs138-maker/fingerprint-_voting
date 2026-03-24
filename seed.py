import datetime
import bcrypt
from app import create_app
from extensions import db
from models import User, Election, Candidate

def seed():
    app = create_app()
    with app.app_context():
        # Check if election already exists
        if Election.query.first():
            print("Election already exists! Skipping seed.")
            return

        admin = User.query.filter_by(username='admin').first()
        admin_id = admin.id if admin else 1
        
        election = Election(
            title='Demo Presidential Election',
            description='A seeded election for testing the voting platform.',
            start_date=datetime.datetime.utcnow() - datetime.timedelta(days=1),
            end_date=datetime.datetime.utcnow() + datetime.timedelta(days=7),
            is_active=True,
            created_by=admin_id
        )
        db.session.add(election)
        db.session.flush() 
        
        c1 = Candidate(name='Alice Johnson', party='Forward Party', election_id=election.id, bio='Focuses on technology.')
        c2 = Candidate(name='Bob Smith', party='Progressive Party', election_id=election.id, bio='Focuses on infrastructure.')
        db.session.add_all([c1, c2])
        
        if not User.query.filter_by(username='testvoter').first():
            voter_password = bcrypt.hashpw('voter123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            voter = User(
                username='testvoter',
                email='voter@votesecure.com',
                password_hash=voter_password,
                full_name='Test Voter',
                role='voter',
                is_verified=True,
                national_id='VOTER001'
            )
            db.session.add(voter)
        
        db.session.commit()
        print("Successfully seeded an Election, Candidates, and a Voter!")

if __name__ == '__main__':
    seed()
