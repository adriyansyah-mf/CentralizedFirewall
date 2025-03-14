from sqlalchemy import Table, Column, BigInteger, Unicode, UUID, String

from core.db import meta

AdminModel = Table(
    'admin', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('name', Unicode(100), nullable=False, unique=True),
    Column('password', Unicode(250), nullable=False),
    Column('uuid', UUID(as_uuid=True), primary_key=True),
    Column('level', String(20), default='admin'),
    Column('api_key', String(250), nullable=True, unique=True),

)
