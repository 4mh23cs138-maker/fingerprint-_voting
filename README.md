# 🛡️ VoteSecure AI — Biometric Voting System

An AI-powered biometric voting system with blockchain integrity, fraud detection, and real-time analytics.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![OpenCV](https://img.shields.io/badge/OpenCV-4.8-red?logo=opencv)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-orange?logo=tensorflow)

## ✨ Features

### 🔐 Authentication
- **Fingerprint-based authentication** using OpenCV (ORB) and CNN models
- **Multi-factor authentication** with TOTP-based OTP
- **JWT token-based** secure sessions

### 🗳️ Voting System
- One-person-one-vote enforcement (biometric + database unique constraints)
- Real-time vote casting with confirmation
- Candidate selection with party information

### 🤖 AI Features
- **Fingerprint Matching**: Dual-mode ORB feature matching + CNN embedding comparison
- **Fraud Detection**: Rapid voting detection, IP anomaly analysis, voting pattern analysis, duplicate biometric scanning

### ⛓️ Blockchain
- Custom blockchain implementation with proof-of-work
- Each vote stored as an immutable block
- Chain verification for integrity validation

### 📊 Dashboard
- Real-time voting statistics with Chart.js
- Voter turnout analytics
- Winner tracking and candidate comparison
- Admin overview with system health metrics

### 👨‍💼 Admin Panel
- Full candidate CRUD with image uploads
- Voter registry with verification controls
- Election lifecycle management (create, pause, activate)
- Fraud analysis reports and audit logs

### 🔒 Security
- bcrypt password hashing
- JWT token authentication
- Rate limiting (Flask-Limiter)
- CSRF protection
- Input validation and sanitization
- Unique database constraints for vote integrity

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip or uv

### Setup

```bash
# Clone the repository
cd fingerprint-_voting

# Create virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The app will be available at: **http://localhost:5000**

### Default Admin Login
- **Username:** `admin`
- **Password:** `admin123`

## 📁 Project Structure

```
fingerprint-_voting/
├── app.py                  # Flask application factory & entry point
├── config.py               # Configuration management
├── extensions.py           # Flask extensions initialization
├── models.py               # SQLAlchemy database models
├── blockchain.py           # Blockchain implementation
├── fingerprint_engine.py   # AI fingerprint matching engine
├── fraud_detection.py      # AI fraud detection system
├── routes_auth.py          # Authentication API routes
├── routes_admin.py         # Admin panel API routes
├── routes_vote.py          # Voting API routes
├── requirements.txt        # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css       # Design system & global styles
│   ├── js/
│   │   └── api.js          # API client & utilities
│   ├── index.html          # Login/Register page
│   ├── voter.html          # Voter dashboard
│   ├── admin.html          # Admin panel
│   └── results.html        # Public results page
└── uploads/
    ├── fingerprints/       # Stored fingerprint images
    └── candidates/         # Candidate photos
```

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new voter |
| POST | `/api/auth/login` | Login with credentials |
| POST | `/api/auth/verify-otp` | Verify OTP code |
| POST | `/api/auth/generate-otp` | Generate new OTP |
| POST | `/api/auth/verify-fingerprint` | Verify fingerprint |
| POST | `/api/auth/enroll-fingerprint` | Enroll fingerprint |
| GET | `/api/auth/me` | Get user profile |

### Voting
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vote/elections` | Get active elections |
| POST | `/api/vote/cast` | Cast a vote |
| GET | `/api/vote/results/:id` | Get election results |
| GET | `/api/vote/blockchain/verify` | Verify blockchain |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/admin/candidates` | Manage candidates |
| GET | `/api/admin/voters` | List voters |
| POST | `/api/admin/voters/:id/verify` | Verify voter identity |
| GET/POST | `/api/admin/elections` | Manage elections |
| GET | `/api/admin/fraud-analysis/:id` | Run fraud analysis |
| GET | `/api/admin/audit-logs` | View audit logs |

## 🛡️ Security Considerations

- All passwords are hashed with bcrypt
- API endpoints protected with JWT
- Rate limiting prevents brute force attacks
- Unique constraints prevent double voting
- CSRF protection on form submissions
- Voter fingerprint hashes checked for duplicates
- Blockchain provides immutable audit trail

## 📜 License

MIT License