"""evidence-led finding validation

Revision ID: d1e6c4a9b7f2
Revises: c9d5b3e8f2a1
Create Date: 2026-11-19 00:15:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d1e6c4a9b7f2"
down_revision: Union[str, None] = "c9d5b3e8f2a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_candidates",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("statement", sa.String(length=2000), nullable=False),
        sa.Column("impact", sa.String(length=2000), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('candidate', 'needs_validation', 'validated', 'rejected')", name="ck_finding_status"),
        sa.ForeignKeyConstraint(["investigation_id"], ["research_investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["research_hypotheses.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_investigation_status", "finding_candidates", ["investigation_id", "status"])

    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("relation IN ('originating', 'supporting', 'contradicting', 'independent')", name="ck_finding_evidence_relation"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding_candidates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["evidence_observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id", "observation_id", "relation"),
    )

    op.create_table(
        "independent_validations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("validator_id", sa.String(length=128), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.String(length=2000), nullable=False),
        sa.Column("reproducible", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("verdict IN ('confirmed', 'rejected', 'inconclusive')", name="ck_validation_verdict"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding_candidates.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_validations_finding", "independent_validations", ["finding_id"])

    op.create_table(
        "validation_evidence",
        sa.Column("validation_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["validation_id"], ["independent_validations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["evidence_observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("validation_id", "observation_id"),
    )


def downgrade() -> None:
    op.drop_table("validation_evidence")
    op.drop_index("ix_validations_finding", table_name="independent_validations")
    op.drop_table("independent_validations")
    op.drop_table("finding_evidence")
    op.drop_index("ix_findings_investigation_status", table_name="finding_candidates")
    op.drop_table("finding_candidates")
