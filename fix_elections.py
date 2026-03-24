import datetime
from app import create_app
from extensions import db
from models import Election, Candidate
from flask import json

def fix_elections():
    app = create_app()
    with app.app_context():
        elections = Election.query.all()
        print(f"Elections found: {len(elections)}")
        for e in elections:
            print(f"Election {e.id}: '{e.title}'  - Active: {e.is_active} - Start: {e.start_date} - End: {e.end_date} - Ongoing: {e.is_ongoing()}")
            
            # Force it to be active right now
            e.is_active = True
            e.start_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            e.end_date = datetime.datetime.utcnow() + datetime.timedelta(days=7)
            
            # Print if there are candidates
            candidates = Candidate.query.filter_by(election_id=e.id).all()
            print(f"  Candidates for this election: {len(candidates)}")
            if len(candidates) == 0:
                print("  No candidates found! Creating dummies...")
                c1 = Candidate(name='Alice Johnson', party='Forward Party', election_id=e.id, bio='Focuses on technology.')
                c2 = Candidate(name='Bob Smith', party='Progressive Party', election_id=e.id, bio='Focuses on infrastructure.')
                db.session.add_all([c1, c2])

        db.session.commit()
        print("Done fixing elections.")

if __name__ == '__main__':
    fix_elections()
