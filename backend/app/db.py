from sqlmodel import SQLModel, create_engine

sqlite_url = "sqlite:///./chat.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def init_db():
    from . import models
    SQLModel.metadata.create_all(engine)
