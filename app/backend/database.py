from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "security_workspace.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DATABASE_PATH}")


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_schema() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        existing = {column["name"] for column in inspect(engine).get_columns("sigma_events")}
        with engine.begin() as connection:
            for column in ("OriginalFileName", "ParentCommandLine"):
                if column not in existing:
                    connection.exec_driver_sql(f'ALTER TABLE sigma_events ADD COLUMN "{column}" TEXT')
        artifact_columns = {
            column["name"] for column in inspect(engine).get_columns("sigma_rule_artifacts")
        }
        with engine.begin() as connection:
            for column in ("tags", "techniques"):
                if column not in artifact_columns:
                    connection.exec_driver_sql(f'ALTER TABLE sigma_rule_artifacts ADD COLUMN "{column}" JSON')
            if "compatibility" not in artifact_columns:
                connection.exec_driver_sql(
                    'ALTER TABLE sigma_rule_artifacts ADD COLUMN "compatibility" VARCHAR(30) DEFAULT "compatible"'
                )
            if "last_error" not in artifact_columns:
                connection.exec_driver_sql('ALTER TABLE sigma_rule_artifacts ADD COLUMN "last_error" TEXT')
        finding_columns = {column["name"] for column in inspect(engine).get_columns("findings")}
        finding_migrations = {
            "correlation_key": "VARCHAR(160)",
            "rule_ids": "JSON",
            "risk_score": "INTEGER DEFAULT 0",
            "confidence": "INTEGER DEFAULT 0",
            "first_seen": "DATETIME",
            "last_seen": "DATETIME",
            "signal_count": "INTEGER DEFAULT 0",
            "suppressed_signal_count": "INTEGER DEFAULT 0",
        }
        with engine.begin() as connection:
            for column, data_type in finding_migrations.items():
                if column not in finding_columns:
                    connection.exec_driver_sql(f'ALTER TABLE findings ADD COLUMN "{column}" {data_type}')
            connection.exec_driver_sql(
                'CREATE UNIQUE INDEX IF NOT EXISTS "ix_findings_correlation_key" ON findings (correlation_key)'
            )


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
