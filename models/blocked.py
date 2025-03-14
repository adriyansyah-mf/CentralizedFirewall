from sqlalchemy import Table, Column, BigInteger, Unicode, Boolean

from core.db import meta

BlockedModel = Table(
    'block', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('mal_ip', Unicode(100), nullable=False, unique=True),
    Column('hostname', Unicode(100), nullable=False, unique=False),
    Column('is_blocked', Boolean, nullable=False, default=False),
    Column('executed_time', BigInteger, nullable=True),

)
