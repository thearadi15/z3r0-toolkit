"""endpoint intelligence

Revision ID: a7c5e1f2d3b4
Revises: 9e1a3c2d4b5f
Create Date: 2026-11-18 17:10:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a7c5e1f2d3b4"
down_revision: Union[str, None] = "9e1a3c2d4b5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "intelligence_assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=False),
        sa.Column("scheme", sa.String(length=8), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "host", "scheme", "port", name="uq_intelligence_asset_origin"),
    )
    op.create_index("ix_intelligence_assets_project_host", "intelligence_assets", ["project_id", "host"])

    op.create_table(
        "intelligence_endpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("host", sa.String(length=253), nullable=True),
        sa.Column("scheme", sa.String(length=8), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("parameter_shape", sa.JSON(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("origin_declared", sa.Boolean(), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "host", "scheme", "port", "method", "path", name="uq_intelligence_endpoint_identity"),
    )
    op.create_index("ix_intelligence_endpoints_project_priority", "intelligence_endpoints", ["project_id", "priority_score"])

    op.create_table(
        "endpoint_evidence",
        sa.Column("endpoint_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["intelligence_endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["evidence_observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("endpoint_id", "observation_id"),
    )


def downgrade() -> None:
    op.drop_table("endpoint_evidence")
    op.drop_index("ix_intelligence_endpoints_project_priority", table_name="intelligence_endpoints")
    op.drop_table("intelligence_endpoints")
    op.drop_index("ix_intelligence_assets_project_host", table_name="intelligence_assets")
    op.drop_table("intelligence_assets")
