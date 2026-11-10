"""Explicit pre-0010 schema for regression cases concerning unresolved identities.

These cases test the supported 0009-to-0010 transition, not the final schema.
All foreign keys, checks and indexes remain; only the historically nullable role
column differs. Final-schema tests separately require rejection of NULL roles.
"""
from sqlalchemy import MetaData
from app.models import Base
from scripts.run_phase1_tests import require_memory_url


def create_transition_schema(engine):
    require_memory_url(engine.url)
    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        table.to_metadata(metadata)
    metadata.tables["users"].c.organization_role.nullable = True
    metadata.create_all(engine)
