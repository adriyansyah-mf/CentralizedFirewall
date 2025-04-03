from sqlalchemy import Table, Column, BigInteger, Unicode, DateTime, ForeignKey, Text, Boolean, UUID, String

from core.db import meta

IocModel = Table(
    'iocs', meta,
    Column('id', BigInteger, primary_key=True, autoincrement=True),
    Column('ip_address', Unicode(100), nullable=True, unique=False),
    Column('is_process', Boolean, nullable=True, unique=False),
    Column('comment', Text, nullable=True, unique=False),
    Column('hostname', Unicode(100), nullable=True, unique=False),
    Column('counter', BigInteger, nullable=True, unique=False),
)
