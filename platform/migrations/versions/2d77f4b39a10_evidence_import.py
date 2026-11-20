"""evidence_import

Revision ID: 2d77f4b39a10
Revises: fa46ba4515b1
Create Date: 2026-11-17 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2d77f4b39a10"
down_revision: Union[str, None] = "fa46ba4515b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_tool", sa.String(length=80), nullable=False),
        sa.Column("source_version", sa.String(length=80), nullable=True),
        sa.Column("artifact_name", sa.String(length=255), nullable=True),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("run_status", sa.String(length=16), nullable=False),
        sa.Column("coverage_note", sa.Text(), nullable=True),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("redacted_field_count", sa.Integer(), nullable=False),
        sa.Column("imported_by", sa.String(length=128), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "payload_sha256", name="uq_evidence_project_payload"),
    )
    op.create_index(
        "ix_evidence_project_imported",
        "evidence_artifacts",
        ["project_id", "imported_at"],
        unique=False,
    )
    op.create_table(
        "evidence_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=2048), nullable=False),
        sa.Column("source_record_id", sa.String(length=128), nullable=True),
        sa.Column("record_sha256", sa.String(length=64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["evidence_artifacts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", "ordinal", name="uq_evidence_observation_ordinal"),
    )
    op.create_index(
        "ix_evidence_observation_kind",
        "evidence_observations",
        ["artifact_id", "kind"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_observation_kind", table_name="evidence_observations")
    op.drop_table("evidence_observations")
    op.drop_index("ix_evidence_project_imported", table_name="evidence_artifacts")
    op.drop_table("evidence_artifacts")
