"""Add username to User model

Revision ID: 1cd1a378221b
Revises: 240109aeeb62
Create Date: 2025-04-27 17:44:54.900722

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1cd1a378221b'
down_revision = '240109aeeb62'
branch_labels = None
depends_on = None


def upgrade():
    # Add 'username' column to the 'profiles' table
    with op.batch_alter_table('profiles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=50), nullable=False))
        # Assign a name to the unique constraint
        batch_op.create_unique_constraint('uq_username', ['username'])  # 'uq_username' is the constraint name

def downgrade():
    with op.batch_alter_table('profiles', schema=None) as batch_op:
        # Drop the unique constraint by name
        batch_op.drop_constraint('uq_username', type_='unique')
        batch_op.drop_column('username')
