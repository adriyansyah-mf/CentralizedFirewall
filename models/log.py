from sqlalchemy import Table, Column, BigInteger, Unicode

from core.db import meta

LogsModel = Table(
    'activity_log', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('activity', Unicode(100), nullable=False, unique=False),

)
