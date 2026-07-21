from flask import Flask, jsonify, request, render_template
import os
import hashlib
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-prod')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simulated in-memory user store (pas de DB pour simplifier)
USERS = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "user1": hashlib.sha256("password1".encode()).hexdigest(),
}

@app.route('/')
def index():
    return jsonify({"message": "DevSecOps API is running", "status": "healthy"})

@app.route('/api/health', methods=['GET'])
def health():
    """Endpoint de health check pour le pipeline CI/CD"""
    return jsonify({
        "status": "healthy",
        "version": os.environ.get("APP_VERSION", "1.0.0"),
        "environment": os.environ.get("FLASK_ENV", "development")
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    """Authentification basique avec hachage du mot de passe"""
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data['username']
    password_hash = hashlib.sha256(data['password'].encode()).hexdigest()

    if USERS.get(username) == password_hash:
        logger.info(f"Login successful for user: {username}")
        return jsonify({"message": "Login successful", "user": username}), 200
    else:
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/users', methods=['GET'])
def get_users():
    """Retourne la liste des utilisateurs (sans les mots de passe)"""
    return jsonify({"users": list(USERS.keys())}), 200

@app.route('/api/secure-data', methods=['GET'])
def secure_data():
    """Endpoint simulant des données sensibles protégées"""
    token = request.headers.get('X-Auth-Token')
    if not token or token != os.environ.get('API_TOKEN', 'test-token-123'):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"data": "Ceci est une donnée sécurisée", "level": "confidential"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)