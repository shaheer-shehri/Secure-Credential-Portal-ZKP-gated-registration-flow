import os
import sys

# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_project import app, db

def init_db():
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("Tables created successfully!")

if __name__ == "__main__":
    init_db()