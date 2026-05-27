import pytest
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_returns_200(client):
    response = client.get('/api/health')
    assert response.status_code == 200

def test_health_returns_json(client):
    response = client.get('/api/health')
    data = json.loads(response.data)
    assert data['status'] == 'healthy'

def test_login_success(client):
    response = client.post('/api/login',
        json={'username': 'admin', 'password': 'admin123'},
        content_type='application/json')
    assert response.status_code == 200

def test_login_wrong_password(client):
    response = client.post('/api/login',
        json={'username': 'admin', 'password': 'wrongpassword'},
        content_type='application/json')
    assert response.status_code == 401

def test_login_missing_fields(client):
    response = client.post('/api/login',
        json={'username': 'admin'},
        content_type='application/json')
    assert response.status_code == 400

def test_get_users(client):
    response = client.get('/api/users')
    assert response.status_code == 200

def test_secure_data_no_token(client):
    response = client.get('/api/secure-data')
    assert response.status_code == 401