from datetime import datetime
from pymongo.database import Database

def log_event(db: Database, actor: str, action: str, details: dict = None):
    if details is None:
        details = {}

    log_entry = {
        "timestamp": datetime.utcnow(),
        "actor": actor,
        "action": action,
        "details": details
    }
    db.audit_log.insert_one(log_entry)
