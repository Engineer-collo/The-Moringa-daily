"""add requested_admin field

Revision ID: 9c5174d94190
Revises: 6ee29206939c
Create Date: 2025-05-11 15:04:36.656738

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9c5174d94190'
down_revision = '6ee29206939c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('requested_admin', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('requested_admin')

    # ### end Alembic commands ###
