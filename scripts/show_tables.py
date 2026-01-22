from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import inspect
from web_project import app, db

with app.app_context():
    insp = inspect(db.engine)
    print('Tables:', insp.get_table_names())
