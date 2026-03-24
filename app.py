"""
Main Flask application factory and entry point.
"""
import os
import bcrypt
from flask import Flask, send_from_directory, send_file, jsonify
from config import config, Config
from extensions import db, login_manager, mail, limiter, csrf
from models import User
from blockchain import Blockchain


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    app = Flask(__name__, static_folder='static', static_url_path='/static')
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    
    Config.init_app(app)
    
    # Register blueprints
    from routes_auth import auth_bp
    from routes_admin import admin_bp
    from routes_vote import vote_bp
    
    # Exempt all API blueprints from CSRF (they use JWT tokens instead)
    csrf.exempt(auth_bp)
    csrf.exempt(admin_bp)
    csrf.exempt(vote_bp)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(vote_bp)
    
    # Serve uploaded files
    @app.route('/uploads/<path:filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    # Serve main HTML pages
    @app.route('/')
    def index():
        return send_file('static/index.html')
    
    @app.route('/admin')
    def admin_page():
        return send_file('static/admin.html')
    
    @app.route('/voter')
    def voter_page():
        return send_file('static/voter.html')
    
    @app.route('/results')
    def results_page():
        return send_file('static/results.html')
    
    # Health check
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'healthy', 'version': '1.0.0'})
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({'error': 'Internal server error'}), 500
    
    # Create tables and seed data
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            admin = User(
                username='admin',
                email='admin@votesecure.com',
                password_hash=admin_password,
                full_name='System Administrator',
                role='admin',
                is_verified=True,
                national_id='ADMIN001'
            )
            db.session.add(admin)
            db.session.commit()
            print("[SUCCESS] Admin user created (username: admin, password: admin123)")
        
        # Initialize blockchain genesis block
        Blockchain.create_genesis_block()
        print("[SUCCESS] Blockchain initialized")
    
    return app


# Create the application instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
