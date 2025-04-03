from sqlalchemy import Table, Column, BigInteger, Unicode

from core.db import meta

WhitelistModel = Table(
    'whitelist', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('ip', Unicode(100), nullable=False, unique=True),
)
