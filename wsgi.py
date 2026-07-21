import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app'))

from app import app

application = app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)