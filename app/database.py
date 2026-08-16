import os
from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = os.environ.get("CIRA_DATABASE_URL", "sqlite:///./cira.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
