"""SQLAlchemy database setup for the Assurance platform."""
import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Paths - data is always stored in <project_root>/data/assurance.db
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ASSURANCE_DB overrides the file, so the test suite can run against its own
# database instead of deleting the one the platform ships loaded with.
DB_PATH = os.environ.get("ASSURANCE_DB") or os.path.join(DATA_DIR, "assurance.db")

# SQLite is perfectly capable of serving a room full of people reading at
# once, but not with the defaults.
#
#   pool_size / max_overflow  the default pool is five connections. Twenty
#                             people opening the dashboard together queued on
#                             those five and waited seconds for a page that
#                             takes a fraction of a second on its own.
#   WAL                       the default journal blocks every reader for the
#                             whole of a write. An upload takes tens of
#                             seconds; under WAL, readers carry on against the
#                             last committed state instead of freezing.
#   busy_timeout              two writes at the same instant should wait for
#                             each other, not fail with "database is locked".
#   synchronous=NORMAL        safe under WAL, and much faster on network disks
#                             of the kind a cloud instance has.
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_size=20,
    max_overflow=20,
    pool_recycle=3600,
    pool_pre_ping=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
