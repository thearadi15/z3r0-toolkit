"""evidence_source_digest

Revision ID: 71bc38d2a6f4
Revises: 2d77f4b39a10
Create Date: 2026-11-17 11:15:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "71bc38d2a6f4"
down_revision: Union[str, None] = "2d77f4b39a10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "evidence_artifacts",
        sa.Column("source_sha256", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("evidence_artifacts", "source_sha256")
