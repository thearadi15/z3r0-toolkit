"""supervisor lifecycle

Revision ID: 9e1a3c2d4b5f
Revises: 71bc38d2a6f4
Create Date: 2026-11-17 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "9e1a3c2d4b5f"
down_revision: Union[str, None] = "71bc38d2a6f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "research_investigations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("objective", sa.String(length=2000), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("budget_limit_units", sa.Integer(), nullable=False),
        sa.Column("budget_used_units", sa.Integer(), nullable=False),
        sa.Column("iteration_limit", sa.Integer(), nullable=False),
        sa.Column("iterations_used", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("budget_limit_units > 0", name="ck_investigation_budget_positive"),
        sa.CheckConstraint("budget_used_units >= 0 AND budget_used_units <= budget_limit_units", name="ck_investigation_budget_within_limit"),
        sa.CheckConstraint("iteration_limit > 0", name="ck_investigation_iterations_positive"),
        sa.CheckConstraint("iterations_used >= 0 AND iterations_used <= iteration_limit", name="ck_investigation_iterations_within_limit"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["research_tasks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_id"], ["scopes.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", name="uq_investigation_task"),
    )
    op.create_index("ix_investigations_project_status", "research_investigations", ["project_id", "status"])

    op.create_table(
        "research_hypotheses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("statement", sa.String(length=2000), nullable=False),
        sa.Column("expected_vulnerable_behavior", sa.String(length=2000), nullable=False),
        sa.Column("expected_secure_behavior", sa.String(length=2000), nullable=False),
        sa.Column("potential_impact", sa.String(length=2000), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_hypothesis_confidence_range"),
        sa.ForeignKeyConstraint(["investigation_id"], ["research_investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypotheses_investigation_status", "research_hypotheses", ["investigation_id", "status"])

    op.create_table(
        "hypothesis_evidence",
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("relation IN ('supporting', 'contradicting')", name="ck_hypothesis_evidence_relation"),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["research_hypotheses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["evidence_observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("hypothesis_id", "observation_id", "relation"),
    )
    op.create_index("ix_hypothesis_evidence_observation", "hypothesis_evidence", ["observation_id"])

    op.create_table(
        "research_proposals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("investigation_id", sa.String(length=36), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("scope_id", sa.String(length=36), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.String(length=2000), nullable=False),
        sa.Column("budget_units", sa.Integer(), nullable=False),
        sa.Column("iteration_units", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("budget_units > 0", name="ck_proposal_budget_positive"),
        sa.CheckConstraint("iteration_units > 0", name="ck_proposal_iterations_positive"),
        sa.ForeignKeyConstraint(["investigation_id"], ["research_investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["hypothesis_id"], ["research_hypotheses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_id"], ["scopes.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proposals_investigation_status", "research_proposals", ["investigation_id", "status"])

    op.create_table(
        "proposal_evidence",
        sa.Column("proposal_id", sa.String(length=36), nullable=False),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["proposal_id"], ["research_proposals.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["evidence_observations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("proposal_id", "observation_id"),
    )
    op.create_index("ix_proposal_evidence_observation", "proposal_evidence", ["observation_id"])


def downgrade() -> None:
    op.drop_index("ix_proposal_evidence_observation", table_name="proposal_evidence")
    op.drop_table("proposal_evidence")
    op.drop_index("ix_proposals_investigation_status", table_name="research_proposals")
    op.drop_table("research_proposals")
    op.drop_index("ix_hypothesis_evidence_observation", table_name="hypothesis_evidence")
    op.drop_table("hypothesis_evidence")
    op.drop_index("ix_hypotheses_investigation_status", table_name="research_hypotheses")
    op.drop_table("research_hypotheses")
    op.drop_index("ix_investigations_project_status", table_name="research_investigations")
    op.drop_table("research_investigations")
