"""
Blockchain module for immutable vote storage.
Each vote is stored as a block with cryptographic hashing.
"""
import hashlib
import json
import datetime
from extensions import db
from models import BlockchainBlock


class Blockchain:
    """Simple blockchain implementation for vote integrity."""
    
    DIFFICULTY = 2  # Number of leading zeros required in hash
    
    @staticmethod
    def calculate_hash(index, timestamp, vote_data, previous_hash, nonce):
        """Calculate SHA-256 hash of block data."""
        block_string = json.dumps({
            'index': index,
            'timestamp': str(timestamp),
            'vote_data': vote_data,
            'previous_hash': previous_hash,
            'nonce': nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    @staticmethod
    def proof_of_work(index, timestamp, vote_data, previous_hash) -> tuple[int, str]:
        """Simple proof of work algorithm."""
        nonce = 0
        while True:
            hash_value = Blockchain.calculate_hash(
                index, timestamp, vote_data, previous_hash, nonce
            )
            if str(hash_value).startswith('0' * int(Blockchain.DIFFICULTY)):
                return nonce, str(hash_value)
            nonce += 1
    
    @staticmethod
    def get_latest_block():
        """Get the latest block from the chain."""
        return BlockchainBlock.query.order_by(BlockchainBlock.index.desc()).first()
    
    @staticmethod
    def create_genesis_block():
        """Create the first block in the chain."""
        existing = BlockchainBlock.query.filter_by(index=0).first()
        if existing:
            return existing
        
        timestamp = datetime.datetime.utcnow()
        vote_data = json.dumps({'genesis': True, 'message': 'Genesis Block - Voting System Initialized'})
        previous_hash = '0' * 64
        
        nonce, hash_value = Blockchain.proof_of_work(0, timestamp, vote_data, previous_hash)
        
        genesis_block = BlockchainBlock(
            index=0,
            timestamp=timestamp,
            vote_data=vote_data,
            previous_hash=previous_hash,
            nonce=nonce,
            hash=hash_value
        )
        db.session.add(genesis_block)
        db.session.commit()
        return genesis_block
    
    @staticmethod
    def add_vote_block(user_id, candidate_id, election_id):
        """Add a new vote as a block to the blockchain."""
        latest_block = Blockchain.get_latest_block()
        if not latest_block:
            latest_block = Blockchain.create_genesis_block()
        
        new_index = latest_block.index + 1
        timestamp = datetime.datetime.utcnow()
        
        # Vote data (hashed user_id for privacy)
        user_hash = hashlib.sha256(str(user_id).encode()).hexdigest()
        vote_data = json.dumps({
            'voter_hash': user_hash,
            'candidate_id': candidate_id,
            'election_id': election_id,
            'timestamp': str(timestamp)
        })
        
        nonce, hash_value = Blockchain.proof_of_work(
            new_index, timestamp, vote_data, latest_block.hash
        )
        
        new_block = BlockchainBlock(
            index=new_index,
            timestamp=timestamp,
            vote_data=vote_data,
            previous_hash=latest_block.hash,
            nonce=nonce,
            hash=hash_value
        )
        db.session.add(new_block)
        db.session.commit()
        
        return new_block
    
    @staticmethod
    def verify_chain():
        """Verify the integrity of the entire blockchain."""
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.index).all()
        
        if not blocks:
            return True, "Chain is empty"
        
        for i in range(1, len(blocks)):
            current = blocks[i]
            previous = blocks[i - 1]
            
            # Check if previous hash matches
            if current.previous_hash != previous.hash:
                return False, f"Chain broken at block {current.index}: previous hash mismatch"
            
            # Verify current block hash
            calculated_hash = Blockchain.calculate_hash(
                current.index, current.timestamp, current.vote_data,
                current.previous_hash, current.nonce
            )
            if calculated_hash != current.hash:
                return False, f"Chain broken at block {current.index}: hash mismatch"
        
        return True, f"Chain verified: {len(blocks)} blocks"
    
    @staticmethod
    def get_chain_data():
        """Get all blocks as a list of dictionaries."""
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.index).all()
        chain = []
        for block in blocks:
            chain.append({
                'index': block.index,
                'timestamp': str(block.timestamp),
                'vote_data': json.loads(block.vote_data),
                'previous_hash': block.previous_hash,
                'nonce': block.nonce,
                'hash': block.hash
            })
        return chain
