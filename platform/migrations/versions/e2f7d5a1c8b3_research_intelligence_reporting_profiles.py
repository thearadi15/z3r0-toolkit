"""CVE/source intelligence, reports, PoCs, and profiles

Revision ID: e2f7d5a1c8b3
Revises: d1e6c4a9b7f2
Create Date: 2026-11-19 22:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e2f7d5a1c8b3"
down_revision: Union[str, None] = "d1e6c4a9b7f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table("advisory_correlations", sa.Column("id",sa.String(36),nullable=False),sa.Column("investigation_id",sa.String(36),nullable=False),sa.Column("advisory_id",sa.String(32),nullable=False),sa.Column("package_name",sa.String(255),nullable=False),sa.Column("affected_version",sa.String(255),nullable=False),sa.Column("source_name",sa.String(80),nullable=False),sa.Column("retrieved_at",sa.DateTime(timezone=True),nullable=False),sa.Column("source_digest",sa.String(64),nullable=False),sa.Column("status",sa.String(24),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("evidence_ids",sa.JSON(),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("status IN ('candidate', 'needs_review', 'accepted', 'rejected')",name="ck_advisory_status"),sa.ForeignKeyConstraint(["investigation_id"],["research_investigations.id"],ondelete="CASCADE"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_advisories_investigation_status","advisory_correlations",["investigation_id","status"])
    op.create_table("source_claims", sa.Column("id",sa.String(36),nullable=False),sa.Column("investigation_id",sa.String(36),nullable=False),sa.Column("repository",sa.String(2048),nullable=False),sa.Column("revision",sa.String(128),nullable=False),sa.Column("claim_type",sa.String(32),nullable=False),sa.Column("file_path",sa.String(2048),nullable=True),sa.Column("line_start",sa.Integer(),nullable=True),sa.Column("line_end",sa.Integer(),nullable=True),sa.Column("statement",sa.String(2000),nullable=False),sa.Column("evidence_digest",sa.String(64),nullable=False),sa.Column("status",sa.String(24),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("status IN ('candidate', 'needs_review', 'accepted', 'rejected')",name="ck_source_claim_status"),sa.ForeignKeyConstraint(["investigation_id"],["research_investigations.id"],ondelete="CASCADE"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_source_claims_investigation_status","source_claims",["investigation_id","status"])
    op.create_table("reproduction_records", sa.Column("id",sa.String(36),nullable=False),sa.Column("investigation_id",sa.String(36),nullable=False),sa.Column("finding_id",sa.String(36),nullable=True),sa.Column("isolation",sa.String(32),nullable=False),sa.Column("outcome",sa.String(24),nullable=False),sa.Column("summary",sa.String(2000),nullable=False),sa.Column("limits",sa.JSON(),nullable=False),sa.Column("evidence_digest",sa.String(64),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("outcome IN ('pending', 'succeeded', 'failed', 'blocked')",name="ck_reproduction_outcome"),sa.ForeignKeyConstraint(["investigation_id"],["research_investigations.id"],ondelete="CASCADE"),sa.ForeignKeyConstraint(["finding_id"],["finding_candidates.id"],ondelete="SET NULL"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_reproduction_investigation","reproduction_records",["investigation_id"])
    op.create_table("safe_poc_templates", sa.Column("id",sa.String(36),nullable=False),sa.Column("finding_id",sa.String(36),nullable=False),sa.Column("title",sa.String(200),nullable=False),sa.Column("format",sa.String(32),nullable=False),sa.Column("content",sa.Text(),nullable=False),sa.Column("approved_target",sa.Text(),nullable=False),sa.Column("status",sa.String(24),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("reviewed_by",sa.String(128),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("status IN ('draft', 'reviewed', 'rejected')",name="ck_poc_status"),sa.ForeignKeyConstraint(["finding_id"],["finding_candidates.id"],ondelete="CASCADE"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_pocs_finding_status","safe_poc_templates",["finding_id","status"])
    op.create_table("research_reports", sa.Column("id",sa.String(36),nullable=False),sa.Column("investigation_id",sa.String(36),nullable=False),sa.Column("title",sa.String(200),nullable=False),sa.Column("summary",sa.Text(),nullable=False),sa.Column("limitations",sa.Text(),nullable=False),sa.Column("findings_json",sa.JSON(),nullable=False),sa.Column("evidence_ids",sa.JSON(),nullable=False),sa.Column("status",sa.String(24),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("reviewed_by",sa.String(128),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("status IN ('draft', 'reviewed', 'published')",name="ck_report_status"),sa.ForeignKeyConstraint(["investigation_id"],["research_investigations.id"],ondelete="CASCADE"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_reports_investigation_status","research_reports",["investigation_id","status"])
    op.create_table("research_profiles", sa.Column("id",sa.String(36),nullable=False),sa.Column("project_id",sa.String(36),nullable=False),sa.Column("name",sa.String(200),nullable=False),sa.Column("cpu_limit_percent",sa.Integer(),nullable=False),sa.Column("memory_limit_mb",sa.Integer(),nullable=False),sa.Column("wall_time_seconds",sa.Integer(),nullable=False),sa.Column("process_limit",sa.Integer(),nullable=False),sa.Column("storage_limit_mb",sa.Integer(),nullable=False),sa.Column("status",sa.String(24),nullable=False),sa.Column("created_by",sa.String(128),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint("cpu_limit_percent >= 1 AND cpu_limit_percent <= 100",name="ck_profile_cpu"),sa.CheckConstraint("memory_limit_mb >= 16 AND memory_limit_mb <= 65536",name="ck_profile_memory"),sa.CheckConstraint("wall_time_seconds >= 1 AND wall_time_seconds <= 86400",name="ck_profile_time"),sa.ForeignKeyConstraint(["project_id"],["projects.id"],ondelete="CASCADE"),sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_profiles_project_status","research_profiles",["project_id","status"])


def downgrade() -> None:
    op.drop_index("ix_profiles_project_status",table_name="research_profiles"); op.drop_table("research_profiles")
    op.drop_index("ix_reports_investigation_status",table_name="research_reports"); op.drop_table("research_reports")
    op.drop_index("ix_pocs_finding_status",table_name="safe_poc_templates"); op.drop_table("safe_poc_templates")
    op.drop_index("ix_reproduction_investigation",table_name="reproduction_records"); op.drop_table("reproduction_records")
    op.drop_index("ix_source_claims_investigation_status",table_name="source_claims"); op.drop_table("source_claims")
    op.drop_index("ix_advisories_investigation_status",table_name="advisory_correlations"); op.drop_table("advisory_correlations")
