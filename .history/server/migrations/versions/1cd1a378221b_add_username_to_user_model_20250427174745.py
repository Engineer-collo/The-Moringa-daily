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
