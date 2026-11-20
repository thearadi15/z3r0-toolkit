"""browser execution gateway

Revision ID: c9d5b3e8f2a1
Revises: b8f4a2c1d7e6
Create Date: 2026-11-18 23:55:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c9d5b3e8f2a1"
down_revision: Union[str, None] = "b8f4a2c1d7e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "browser_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("action_count", sa.Integer(), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column("blocked_requests", sa.Integer(), nullable=False),
        sa.Column("final_url", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("action_count >= 1 AND action_count <= 10", name="ck_browser_action_count_limit"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["research_tasks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_browser_executions_task_created", "browser_executions", ["task_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_browser_executions_task_created", table_name="browser_executions")
    op.drop_table("browser_executions")
