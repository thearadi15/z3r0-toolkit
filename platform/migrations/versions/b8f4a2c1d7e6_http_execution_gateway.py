"""HTTP execution gateway

Revision ID: b8f4a2c1d7e6
Revises: a7c5e1f2d3b4
Create Date: 2026-11-18 23:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b8f4a2c1d7e6"
down_revision: Union[str, None] = "a7c5e1f2d3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "http_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("request_headers", sa.JSON(), nullable=False),
        sa.Column("request_body_sha256", sa.String(length=64), nullable=True),
        sa.Column("request_bytes", sa.Integer(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_headers", sa.JSON(), nullable=False),
        sa.Column("response_sha256", sa.String(length=64), nullable=True),
        sa.Column("response_bytes", sa.Integer(), nullable=False),
        sa.Column("resolved_addresses", sa.JSON(), nullable=False),
        sa.Column("redirect_count", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("request_bytes <= 65536", name="ck_http_request_bytes_limit"),
        sa.CheckConstraint("response_bytes <= 1048576", name="ck_http_response_bytes_limit"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["research_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_http_executions_task_created", "http_executions", ["task_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_http_executions_task_created", table_name="http_executions")
    op.drop_table("http_executions")
