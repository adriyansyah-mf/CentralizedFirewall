from sqlalchemy import Table, Column, BigInteger, Unicode

from core.db import meta

GroupModel = Table(
    'groups', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('groups', Unicode(100), nullable=False, unique=True)
)
