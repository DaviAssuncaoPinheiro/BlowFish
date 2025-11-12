from datetime import datetime
from pymongo.database import Database

def log_event(db: Database, actor: str, action: str, details: dict = None):
    """
    Registra um evento de auditoria no banco de dados.

    :param db: Instância do banco de dados MongoDB.
    :param actor: O usuário que realizou a ação (ex: 'admin', 'user123').
    :param action: A ação realizada (ex: 'USER_LOGIN', 'CREATE_GROUP').
    :param details: Um dicionário com detalhes adicionais sobre o evento.
    """
    if details is None:
        details = {}

    log_entry = {
        "timestamp": datetime.utcnow(),
        "actor": actor,
        "action": action,
        "details": details
    }
    db.audit_log.insert_one(log_entry)
