"""Add master_key_salt to User model

Revision ID: eba120386e9b
Revises: 25bfd120ea89
Create Date: 2024-11-24 23:59:45.200409

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eba120386e9b'
down_revision = '25bfd120ea89'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('master_key_salt', sa.String(length=64), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('master_key_salt')

    # ### end Alembic commands ###