"""zero_knowledge_schema

Revision ID: edb62ca16834
Revises: b1c7d3e59f20
Create Date: 2026-09-20 20:25:05.107283

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "edb62ca16834"
down_revision: str | Sequence[str] | None = "b1c7d3e59f20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.add_column(sa.Column("encrypted_data", sa.LargeBinary(), nullable=False))
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.drop_index(batch_op.f("ix_credentials_service_name"))
        batch_op.drop_constraint(batch_op.f("uq_credentials_service_login"), type_="unique")
        batch_op.drop_column("encrypted_password")
        batch_op.drop_column("encrypted_totp_secret")
        batch_op.drop_column("encrypted_notes")
        batch_op.drop_column("url")
        batch_op.drop_column("service_name")
        batch_op.drop_column("login")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.add_column(sa.Column("login", sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column("service_name", sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column("url", sa.String(length=2048), nullable=True))
        batch_op.add_column(sa.Column("encrypted_notes", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("encrypted_totp_secret", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("encrypted_password", sa.LargeBinary(), nullable=False))
        batch_op.create_unique_constraint(
            batch_op.f("uq_credentials_service_login"), ["service_name", "login"]
        )
        batch_op.create_index(
            batch_op.f("ix_credentials_service_name"), ["service_name"], unique=False
        )
        batch_op.drop_column("deleted_at")
        batch_op.drop_column("encrypted_data")
